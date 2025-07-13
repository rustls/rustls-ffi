use std::collections::HashSet;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs;

use serde::Serialize;
use tree_sitter::{Node, Parser, Query, QueryCursor};
use tree_sitter_md::MarkdownParser;

fn main() -> Result<(), Box<dyn Error>> {
    // Create a C parser.
    let mut parser = Parser::new();
    let language = tree_sitter_c::LANGUAGE;
    parser.set_language(&language.into())?;

    // Parse the .h into an AST.
    let header_file = fs::read_to_string("librustls/src/rustls.h")?;
    //let header_file = fs::read_to_string("test.h")?;
    let header_file_bytes = header_file.as_bytes();
    let tree = parser
        .parse(&header_file, None)
        .ok_or("no tree parsed from input")?;

    // Make sure we have the root node we expect.
    let root = tree.root_node();
    require_kind("translation_unit", root, header_file_bytes)?;

    // Collect up all items we want to document. Returns an error if any
    // items we expect to be documented are missing associated block comments.
    let mut docs = find_doc_items(root, header_file_bytes)?;

    // Cross-link items in comments.
    docs.crosslink_comments()?;

    // Render JSON data.
    println!("{}", serde_json::to_string_pretty(&docs)?);

    Ok(())
}

#[derive(Debug, Default, Serialize)]
struct ApiDocs {
    structs: Vec<StructItem>,
    functions: Vec<FunctionItem>,
    callbacks: Vec<CallbackItem>,
    enums: Vec<EnumItem>,
    externs: Vec<ExternItem>,
    aliases: Vec<TypeAliasItem>,
}

impl ApiDocs {
    fn crosslink_comments(&mut self) -> Result<(), Box<dyn Error>> {
        // Put all anchors into a set. Error for any duplicates.
        let mut anchor_set = HashSet::new();
        for a in self.all_anchors() {
            if !anchor_set.insert(a.to_string()) {
                return Err(format!("duplicate anchor: {a}").into());
            }
        }

        // For each item of each type, crosslink its comment.
        for s in &mut self.structs {
            s.comment.crosslink(&anchor_set)?;
        }
        for f in &mut self.functions {
            f.comment.crosslink(&anchor_set)?;
        }
        for cb in &mut self.callbacks {
            cb.comment.crosslink(&anchor_set)?;
        }
        for e in &mut self.enums {
            e.comment.crosslink(&anchor_set)?;
            for v in &mut e.variants {
                if let Some(comment) = &mut v.comment {
                    comment.crosslink(&anchor_set)?;
                }
            }
        }
        for e in &mut self.externs {
            e.comment.crosslink(&anchor_set)?;
        }
        for a in &mut self.aliases {
            a.comment.crosslink(&anchor_set)?;
        }

        Ok(())
    }

    fn all_anchors(&self) -> impl Iterator<Item = &str> {
        // return all item anchors as a chained iterator
        self.structs
            .iter()
            .map(|s| s.anchor.as_str())
            .chain(self.functions.iter().map(|f| f.anchor.as_str()))
            .chain(self.callbacks.iter().map(|cb| cb.anchor.as_str()))
            .chain(self.enums.iter().map(|e| e.anchor.as_str()))
            .chain(self.externs.iter().map(|e| e.anchor.as_str()))
            .chain(self.aliases.iter().map(|a| a.anchor.as_str()))
    }
}

fn find_doc_items(root: Node, source_code: &[u8]) -> Result<ApiDocs, Box<dyn Error>> {
    // We document all:
    // * type definitions
    // * enum specifiers with an enumerator list (enums outside an inline typedef)
    // * declarations (incls. externs)
    //
    // For bare enums we have to make sure we don't match on just (enum_specifier) because
    // this will match the node in a function decl returning an enum. We want an enum
    // specifier with an enumerator list.
    let query = r#"
    (
        [
            (type_definition)
            (enum_specifier (type_identifier) (enumerator_list))
            (declaration)
        ]
        @doc_item
    )
    "#;
    let language = tree_sitter_c::LANGUAGE;
    let query = Query::new(&language.into(), query)?;

    let mut cursor = QueryCursor::new();
    let matches = cursor.matches(&query, root, source_code);

    let mut items = Vec::default();
    let mut errors = 0;
    for query_match in matches {
        for doc_item_node in query_match.nodes_for_capture_index(0) {
            match process_doc_item(doc_item_node, source_code) {
                Ok(Some(item)) => items.push(item),
                Err(err) => {
                    eprintln!("{err}");
                    errors += 1;
                }
                _ => {}
            }
        }
    }
    if errors > 0 {
        return Err(format!("{errors} errors produced while documenting header file").into());
    }

    let mut api = ApiDocs::default();
    for item in items {
        match item {
            Item::Enum(e) => api.enums.push(e),
            Item::Struct(s) => api.structs.push(s),
            Item::TypeAlias(a) => api.aliases.push(a),
            Item::Callback(cb) => api.callbacks.push(cb),
            Item::Function(f) => api.functions.push(f),
            Item::Extern(e) => api.externs.push(e),
        }
    }

    Ok(api)
}

fn process_doc_item(item: Node, src: &[u8]) -> Result<Option<Item>, Box<dyn Error>> {
    // Get the item's previous sibling in the tree.
    let Some(prev) = item.prev_sibling() else {
        return Err(node_error("to-be-documented item without previous item", item, src).into());
    };

    // If we're looking at an enum node, but it's after a typedef, skip.
    // We'll document this enum when we process the typedef.
    if item.kind() == "enum_specifier" && prev.kind() == "typedef" {
        return Ok(None);
    }

    // Try to turn the previous sibling into a comment node. Some items may
    // require this to be Some(_) while others may allow None.
    let (comment, feat_requirement) = comment_and_requirement(prev, src)?;

    let kind = item.kind();
    // Based on the node kind, convert it to an appropriate Item.
    Ok(Some(match kind {
        "type_definition" => process_typedef_item(comment, feat_requirement, item, src)?,
        "enum_specifier" => Item::from(EnumItem::new(comment, feat_requirement, item, src)?),
        "declaration" => process_declaration_item(comment, feat_requirement, item, src)?,
        _ => return Err(format!("unexpected item kind: {kind}").into()),
    }))
}

/// Convert the preceding sibling of a to-be-processed item into associated metadata
///
/// An item `Node` to be processed for documentation will typically have associated
/// metadata `Node`s preceding it in the parse tree. This function returns an optional
/// `Comment` and/or optional `Feature` from processing the sibling `prev` `Node`.
///
/// The potential cases we care about are:
///   * `prev` is not a comment, and not a feature requirement.
///   * `prev` is a Comment, and has no feature requirement before it.
///   * `prev` is a Comment, and has a feature requirement before it.
///   * `prev` is a bare feature requirement
///
/// cbindgen won't create a comment before a feature requirement so we don't have to
/// consider that case.
fn comment_and_requirement(
    prev: Node,
    src: &[u8],
) -> Result<(Option<Comment>, Option<Feature>), Box<dyn Error>> {
    let prev_prev = prev.prev_named_sibling();
    let mut maybe_comment = Comment::new(prev, src).ok();

    // If node wasn't a comment, see if it was an expression_statement
    // that itself was preceded by a comment.  This skips over
    // expression-like preprocessor attributes on function decls.
    if let (None, "expression_statement", Some(prev_prev)) =
        (&maybe_comment, prev.kind(), prev_prev)
    {
        maybe_comment = Comment::new(prev_prev, src).ok();
    }

    // If prev wasn't a comment, see if it was a feature requirement.
    if maybe_comment.is_none() {
        return Ok(match Feature::new(prev, src).ok() {
            Some(feat_req) => (None, Some(feat_req)),
            None => (None, None),
        });
    }

    // Otherwise, check the prev of the comment for a feature requirement
    let Some(prev_prev) = prev_prev else {
        return Ok((maybe_comment, None));
    };

    Ok((maybe_comment, Feature::new(prev_prev, src).ok()))
}

#[derive(Debug, Default, Serialize)]
struct Feature(String);

impl Feature {
    fn new(node: Node, src: &[u8]) -> Result<Self, Box<dyn Error>> {
        // Verify we're looking at a preproc_defined node preceded by a preproc_if node.
        require_kind("preproc_defined", node, src)?;
        if let Some(prev) = node.prev_sibling() {
            require_kind("#if", prev, src)?;
        } else {
            return Err(node_error("feature requirement without previous item", node, src).into());
        }

        let Some(required_define) = node.named_child(0).map(|n| node_text(n, src)) else {
            return Err(node_error("feature requirement without identifier", node, src).into());
        };

        // We assume features have cbindgen defines like "DEFINE_$FEATURE_NAME" and we want to
        // extract "$feature_name".
        Ok(Self(
            required_define
                .strip_prefix("DEFINE_")
                .unwrap_or(&required_define)
                .to_ascii_lowercase(),
        ))
    }
}

impl Display for Feature {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A comment from the header file.
///
/// The comment text is cleaned up to remove leading/trailing C block comment syntax.
/// The remaining text is unaltered with respect to indentation and newlines within the
/// content.
#[derive(Debug, Default, Serialize)]
struct Comment(String);

impl Comment {
    fn new(node: Node, src: &[u8]) -> Result<Self, Box<dyn Error>> {
        require_kind("comment", node, src)?;

        // Convert the node to UTF8 text and then strip the block comment syntax and any
        // leading/trailing newlines.
        let text = node
            .utf8_text(src)
            .unwrap_or_default()
            .lines()
            .map(|line| {
                line.trim()
                    .trim_start_matches("/**")
                    .trim_end_matches("*/")
                    .trim_start_matches('*')
            })
            .collect::<Vec<_>>()
            .join("\n")
            .trim()
            .to_string();

        Ok(Self(text))
    }

    fn crosslink(&mut self, anchors: &HashSet<String>) -> Result<(), Box<dyn Error>> {
        let Some(parser) = MarkdownParser::default().parse(self.0.as_bytes(), None) else {
            return Ok(());
        };

        // Find all the "code_span" items from each inline tree, potentially replacing some content.
        let mut replacements = Vec::new();
        for t in parser.inline_trees() {
            let mut cursor = t.walk();
            if !cursor.goto_first_child() {
                break;
            }
            loop {
                let node = cursor.node();
                if node.kind() != "code_span" {
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                    continue;
                }
                let start = node.start_byte();
                let end = node.end_byte();
                let content = &self.0[start..end].trim_matches('`');
                let anchor = content.trim_end_matches("()").replace('_', "-");

                // If we found an anchor in backticks, make it a link to that anchor.
                if anchors.contains(&anchor) {
                    replacements.push((start, end, format!("[`{content}`](#{anchor})")));
                }

                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        // Apply replacements to comment in reverse to maintain correct byte offsets.
        for (start, end, replacement) in replacements.into_iter().rev() {
            self.0.replace_range(start..end, &replacement);
        }

        Ok(())
    }
}

impl Display for Comment {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn process_typedef_item(
    maybe_comment: Option<Comment>,
    maybe_feature: Option<Feature>,
    item: Node,
    src: &[u8],
) -> Result<Item, Box<dyn Error>> {
    require_kind("type_definition", item, src)?;

    let typedef_node = item.child_by_field_name("type").unwrap();
    let typedef_kind = typedef_node.kind();

    let comment = match (&maybe_comment, item.prev_named_sibling()) {
        // We allow an uncommented type_definition if the previous node was a bare enum_specifier.
        // This happens when an enum has a primitive type repr, like rustls_result. The enum
        // appears without typedef (but with comment), and then a typedef uint32_t appears (without
        // preceding comment). This is OK and doesn't count as an undocumented error.
        //
        // It's important we use prev_named_sibling() for finding the enum_specifier that precedes
        // the typedef. Using prev_sibling() would return an anonymous ';' node.
        (None, Some(sib)) if sib.kind() == "enum_specifier" => Comment::default(),
        _ => require_documented(maybe_comment, item, src)?,
    };

    // Convert the particular item being typedef'd based on kind().
    // We treat function typedefs differently - we want those to be considered callbacks.
    let func_declarator = item
        .child_by_field_name("declarator")
        .map(|n| {
            n.kind() == "function_declarator"
                || (n.kind() == "pointer_declarator"
                    && n.child_by_field_name("declarator")
                        .map(|n| n.kind() == "function_declarator")
                        .unwrap_or_default())
        })
        .unwrap_or_default();
    Ok(match typedef_kind {
        // e.g. `typedef enum rustls_handshake_kind { ... } rustls_handshake_kind;`
        "enum_specifier" => Item::from(EnumItem::new(
            Some(comment),
            maybe_feature,
            typedef_node,
            src,
        )?),

        // e.g. `typedef uint32_t (*rustls_verify_server_cert_callback)(...);`
        "primitive_type" if func_declarator => {
            Item::from(CallbackItem::new(comment, maybe_feature, item, src)?)
        }

        // e.g. `typedef rustls_io_result (*rustls_read_callback)(...);`
        "type_identifier" if func_declarator => {
            Item::from(CallbackItem::new(comment, maybe_feature, item, src)?)
        }

        // e.g. `typedef const struct rustls_certified_key *(*rustls_client_hello_callback)(...);`
        "struct_specifier" if func_declarator => {
            Item::from(CallbackItem::new(comment, maybe_feature, item, src)?)
        }

        // e.g. `typedef struct rustls_accepted rustls_accepted;`
        "struct_specifier" => {
            Item::from(StructItem::new(comment, maybe_feature, typedef_node, src)?)
        }

        // e.g. `typedef int rustls_io_result;`
        "primitive_type" if !func_declarator => {
            Item::from(TypeAliasItem::new(comment, maybe_feature, item, src))
        }

        // e.g. ... well, none so far - but something like `typedef rustls_io_result rustls_funtime_io_result;`.
        "type_identifier" if !func_declarator => {
            Item::from(TypeAliasItem::new(comment, maybe_feature, item, src))
        }

        _ => return Err(format!("unknown typedef kind: {typedef_kind:?}").into()),
    })
}

fn process_declaration_item(
    comment: Option<Comment>,
    maybe_feature: Option<Feature>,
    item: Node,
    src: &[u8],
) -> Result<Item, Box<dyn Error>> {
    require_kind("declaration", item, src)?;

    let comment = require_documented(comment, item, src)?;
    if item.child(0).unwrap().kind() == "storage_class_specifier" {
        // extern is a storage_class_specifier.
        Ok(Item::from(ExternItem::new(
            comment,
            maybe_feature,
            item,
            src,
        )?))
    } else {
        // other non-extern declarations are functions.
        Ok(Item::from(FunctionItem::new(
            comment,
            maybe_feature,
            item,
            src,
        )?))
    }
}

/// An item to be documented from a C header file.
#[derive(Debug)]
enum Item {
    Enum(EnumItem),
    Struct(StructItem),
    TypeAlias(TypeAliasItem),
    Callback(CallbackItem),
    Function(FunctionItem),
    Extern(ExternItem),
}

impl From<EnumItem> for Item {
    fn from(item: EnumItem) -> Self {
        Self::Enum(item)
    }
}

impl From<StructItem> for Item {
    fn from(item: StructItem) -> Self {
        Self::Struct(item)
    }
}

impl From<TypeAliasItem> for Item {
    fn from(item: TypeAliasItem) -> Self {
        Self::TypeAlias(item)
    }
}

impl From<CallbackItem> for Item {
    fn from(item: CallbackItem) -> Self {
        Self::Callback(item)
    }
}

impl From<FunctionItem> for Item {
    fn from(item: FunctionItem) -> Self {
        Self::Function(item)
    }
}

impl From<ExternItem> for Item {
    fn from(item: ExternItem) -> Self {
        Self::Extern(item)
    }
}

/// An enum declaration.
///
/// E.g. `typedef enum rustls_handshake_kind { ... variants ... };`
#[derive(Debug, Serialize)]
struct EnumItem {
    anchor: String,
    comment: Comment,
    feature: Option<Feature>,
    name: String,
    variants: Vec<EnumVariantItem>,
}

impl EnumItem {
    fn new(
        comment: Option<Comment>,
        feature: Option<Feature>,
        enum_spec: Node,
        src: &[u8],
    ) -> Result<Self, Box<dyn Error>> {
        let comment = require_documented(comment, enum_spec, src)?;

        let name = enum_spec
            .child_by_field_name("name")
            .map(|n| node_text(n, src))
            .unwrap();

        // Get the enumerator_list and walk its children, converting each variant to an
        // EnumVariantItem.
        let enumeraor_list = enum_spec.child_by_field_name("body").unwrap();
        let mut cursor = enumeraor_list.walk();
        let variants = enumeraor_list
            .children(&mut cursor)
            .filter_map(|n| EnumVariantItem::new(n, src).ok())
            .collect();

        Ok(Self {
            anchor: name.replace('_', "-").to_ascii_lowercase(),
            comment,
            feature,
            name,
            variants,
        })
    }
}

/// A variant of an Enum.
///
/// E.g. RUSTLS_RESULT_ALERT_UNKNOWN = 7234
#[derive(Debug, Default, Serialize)]
struct EnumVariantItem {
    anchor: String,
    comment: Option<Comment>, // We don't require all enum variants have comments.
    name: String,
    value: String,
}

impl EnumVariantItem {
    fn new(variant_node: Node, src: &[u8]) -> Result<Self, Box<dyn Error>> {
        require_kind("enumerator", variant_node, src)?;

        let name = node_text(variant_node.child_by_field_name("name").unwrap(), src);
        Ok(Self {
            anchor: name.replace('_', "-").to_ascii_lowercase(),
            comment: variant_node
                .prev_sibling()
                .and_then(|n| Comment::new(n, src).ok()),
            name,
            value: node_text(variant_node.child_by_field_name("value").unwrap(), src),
        })
    }
}

/// A structure typedef.
///
/// May have fields (not presently parsed) or no fields (e.g. an opaque struct).
///
/// E.g. `typedef struct rustls_client_config_builder rustls_client_config_builder;`
#[derive(Debug, Serialize)]
struct StructItem {
    anchor: String,
    comment: Comment,
    feature: Option<Feature>,
    name: String,
    text: String,
}

impl StructItem {
    fn new(
        comment: Comment,
        feature: Option<Feature>,
        struct_node: Node,
        src: &[u8],
    ) -> Result<Self, Box<dyn Error>> {
        require_kind("struct_specifier", struct_node, src)?;

        let name = node_text(struct_node.child_by_field_name("name").unwrap(), src);
        Ok(Self {
            anchor: name.replace('_', "-").to_ascii_lowercase(),
            comment,
            feature,
            name,
            text: markup_text(struct_node, src),
        })
    }
}

/// A simple typedef type alias.
///
/// E.g. `typedef int rustls_io_result;`
#[derive(Debug, Serialize)]
struct TypeAliasItem {
    anchor: String,
    comment: Comment,
    feature: Option<Feature>,
    name: String,
    text: String,
}

impl TypeAliasItem {
    fn new(comment: Comment, feature: Option<Feature>, item: Node, src: &[u8]) -> Self {
        let language = tree_sitter_c::LANGUAGE;
        let query = Query::new(&language.into(), "(type_identifier) @name").unwrap();
        let mut cursor = QueryCursor::new();
        let name = cursor
            .matches(&query, item, src)
            .next()
            .map(|m| node_text(m.captures[0].node, src))
            .unwrap();

        Self {
            // Note: we add a 'alias-' prefix for simple type aliases anchors.
            //  We do this because otherwise we end up with two 'rustls-result'
            // anchors. One for the bare enum, and one for the typedef'd type.
            anchor: format!("alias-{}", name.replace("_", "-").to_ascii_lowercase()),
            name,
            comment,
            feature,
            text: markup_text(item, src),
        }
    }
}

/// A function pointer typedef for a callback function.
///
/// E.g. `typedef rustls_io_result (*rustls_read_callback)(void *userdata, ...);`
#[derive(Debug, Serialize)]
struct CallbackItem {
    anchor: String,
    comment: Comment,
    feature: Option<Feature>,
    name: String,
    text: String,
}

impl CallbackItem {
    fn new(
        comment: Comment,
        feature: Option<Feature>,
        typedef: Node,
        src: &[u8],
    ) -> Result<Self, Box<dyn Error>> {
        require_kind("type_definition", typedef, src)?;

        let name = function_identifier(typedef, src);
        Ok(Self {
            anchor: name.replace("_'", "-").to_ascii_lowercase(),
            comment,
            feature,
            name,
            text: markup_text(typedef, src),
        })
    }
}

/// A function prototype definition.
///
/// E.g. `void rustls_acceptor_free(struct rustls_acceptor *acceptor);`
#[derive(Debug, Serialize)]
struct FunctionItem {
    anchor: String,
    comment: Comment,
    feature: Option<Feature>,
    name: String,
    text: String,
}

impl FunctionItem {
    fn new(
        comment: Comment,
        feature: Option<Feature>,
        decl_node: Node,
        src: &[u8],
    ) -> Result<Self, Box<dyn Error>> {
        require_kind("declaration", decl_node, src)?;

        let name = function_identifier(decl_node, src);
        Ok(Self {
            anchor: name.replace('_', "-").to_ascii_lowercase(),
            comment,
            feature,
            name,
            text: markup_text(decl_node, src),
        })
    }
}

/// An extern constant declaration.
///
/// E.g. `extern const uint16_t RUSTLS_ALL_VERSIONS[2];`
#[derive(Debug, Serialize)]
struct ExternItem {
    anchor: String,
    comment: Comment,
    feature: Option<Feature>,
    name: String,
    text: String,
}

impl ExternItem {
    fn new(
        comment: Comment,
        feature: Option<Feature>,
        decl_node: Node,
        src: &[u8],
    ) -> Result<Self, Box<dyn Error>> {
        require_kind("declaration", decl_node, src)?;

        // Query for the first identifier kind child node.
        let language = tree_sitter_c::LANGUAGE;
        let query = Query::new(&language.into(), "(identifier) @name").unwrap();
        let mut cursor = QueryCursor::new();
        let name = cursor
            .matches(&query, decl_node, src)
            .next()
            .map(|m| node_text(m.captures[0].node, src))
            .unwrap();

        Ok(Self {
            anchor: name.replace('_', "-").to_ascii_lowercase(),
            comment,
            feature,
            name,
            text: markup_text(decl_node, src),
        })
    }
}

/// Return a function's name.
///
/// Queries for function names from simple function declarators like
///  `rustls_io_result rustls_acceptor_read_tls(...)`
/// or, pointers to functions that have a parenthesized name like
///  `typedef rustls_io_result (*rustls_read_callback)(...)`
///
/// Panics if there is no match.
fn function_identifier(node: Node, src: &[u8]) -> String {
    let language = tree_sitter_c::LANGUAGE;
    let query = Query::new(
        &language.into(),
        r#"
        [
            (function_declarator
                declarator: (identifier) @name
            )
            (function_declarator
                declarator: (parenthesized_declarator
                    (pointer_declarator
                        (type_identifier) @name
                    )
                )
            )
        ]"#,
    )
    .unwrap();
    let mut cursor = QueryCursor::new();
    let res = cursor
        .matches(&query, node, src)
        .next()
        .map(|m| node_text(m.captures[0].node, src));

    if res.is_none() {
        dbg!(&node.start_position().row);
        dbg!(&node);
    }
    res.unwrap()
}

/// Require that a `Node` correspond to a specific kind of grammar rule.
///
/// Returns an error describing the node's position and the expected vs actual
/// kind if there is a mismatch.
///
/// Once the kind is verified we can lean on the grammar to unwrap() elements
/// we know must exist.
fn require_kind(kind: &str, node: Node, src: &[u8]) -> Result<(), Box<dyn Error>> {
    let found_kind = node.kind();
    match found_kind == kind {
        true => Ok(()),
        false => Err(node_error(format!("expected {kind}, found {found_kind}"), node, src).into()),
    }
}

/// Unwrap a required CommentNode or return an error.
///
/// The error will describe the kind of node that was missing a documentation comment, as well
/// as its location (line/col) in the source code.
fn require_documented(
    comment: Option<Comment>,
    item: Node,
    src: &[u8],
) -> Result<Comment, Box<dyn Error>> {
    comment.ok_or(
        node_error(
            format!("undocumented {kind}", kind = item.kind()),
            item,
            src,
        )
        .into(),
    )
}

fn node_error(prefix: impl Display, n: Node, src: &[u8]) -> String {
    format!(
        "{prefix} on L{line}:{col}: item: {:?}",
        node_text(n, src),
        line = n.start_position().row + 1,
        col = n.start_position().column,
    )
}

/// Convert the node to its textual representation in the source code.
///
/// Returns an empty string if the content isn't valid UTF-8.
fn node_text(node: Node, src: &[u8]) -> String {
    node.utf8_text(src).unwrap_or_default().to_string()
}

/// Convert the node to its textual representation, then decorate it as C
/// markdown code block.
fn markup_text(node: Node, src: &[u8]) -> String {
    format!("```c\n{}\n```", node_text(node, src))
}
