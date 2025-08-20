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
    let docs = find_doc_items(root, header_file_bytes)?;

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

    // Put all anchors into a set. Error for any duplicates.
    let mut anchor_set = HashSet::new();
    for item in &items {
        if !anchor_set.insert(item.anchor().to_string()) {
            return Err(format!("duplicate anchor: {}", item.anchor()).into());
        }
    }

    // Construct the ApiDocs result.
    let mut api = ApiDocs::default();
    for mut item in items {
        item.crosslink(&anchor_set)?;
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

    // Try to turn the previous sibling into item metadata
    let metadata = ItemMetadata::new(prev, src)?;

    let kind = item.kind();
    // Based on the node kind, convert it to an appropriate Item.
    Ok(Some(match kind {
        "type_definition" => process_typedef_item(metadata, item, src)?,
        "enum_specifier" => Item::from(EnumItem::new(metadata, item, src)?),
        "declaration" => process_declaration_item(metadata, item, src)?,
        _ => return Err(format!("unexpected item kind: {kind}").into()),
    }))
}

/// Metadata common to documented items
#[derive(Debug, Default, Serialize)]
struct ItemMetadata {
    /// A comment describing the item
    comment: Option<Comment>,
    /// A feature requirement that must be enabled for the item
    feature: Option<Feature>,
    /// A deprecation message for the item
    deprecation: Option<Deprecation>,
}

impl ItemMetadata {
    /// Convert the preceding sibling of a to-be-processed item into associated metadata
    ///
    /// An item `Node` to be processed for documentation will typically have associated
    /// metadata `Node`s preceding it in the parse tree. This function returns the
    /// `ItemMetadata` that could be found.
    ///
    /// The potential cases we care about are:
    ///   * `prev` is not a comment, and not a feature requirement.
    ///   * `prev` is a Comment, and has no feature requirement before it.
    ///   * `prev` is a Comment, and has a feature requirement before it.
    ///   * `prev` is a Deprecation, and has a comment and feature requirement before it.
    ///   * `prev` is a Deprecation, and has a comment and no feature requirement before it.
    ///   * `prev` is a bare feature requirement
    ///
    /// cbindgen won't create other permutations (e.g. comment before a feature requirement, or
    /// a deprecation before a feature requirement) so we don't have to consider those cases.
    fn new(prev: Node, src: &[u8]) -> Result<Self, Box<dyn Error>> {
        let prev_prev = prev.prev_named_sibling();

        // In the simple case, `prev` is a comment and `prev_prev` may
        // be a feature requirement. Deprecations aren't in play.
        if let Ok(comment) = Comment::new(prev, src) {
            let feature = match prev_prev {
                Some(prev_prev) => Feature::new(prev_prev, src).ok(),
                None => None,
            };
            return Ok(ItemMetadata {
                comment: Some(comment),
                feature,
                deprecation: None,
            });
        }

        // `prev` is a deprecation, `prev_prev` may be a comment, and `prev_prev_prev`
        // may be a feature requirement.
        if let Ok(deprecation) = Deprecation::new(prev, src) {
            let comment = match prev_prev {
                Some(prev_prev) => Comment::new(prev_prev, src).ok(),
                None => None,
            };
            let prev_prev_prev = prev_prev.and_then(|prev_prev| prev_prev.prev_named_sibling());
            let feature = match prev_prev_prev {
                Some(prev_prev_prev) => Feature::new(prev_prev_prev, src).ok(),
                None => None,
            };
            return Ok(ItemMetadata {
                comment,
                feature,
                deprecation: Some(deprecation),
            });
        }

        // If `prev` wasn't a comment, or an expression_statement preceded by a comment,
        // then it's either a bare feature requirement without a deprecation or we have no
        // metadata to return.
        Ok(ItemMetadata {
            comment: None,
            feature: Feature::new(prev, src).ok(),
            deprecation: None,
        })
    }

    // If the metadata has a comment, update the content with crosslinks using the provided anchors
    fn crosslink(&mut self, anchors: &HashSet<String>) -> Result<(), Box<dyn Error>> {
        match &mut self.comment {
            Some(comment) => comment.crosslink(anchors),
            None => Ok(()),
        }
    }
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

#[derive(Debug, Default, Serialize)]
struct Deprecation(String);

impl Deprecation {
    fn new(node: Node, src: &[u8]) -> Result<Self, Box<dyn Error>> {
        require_kind("expression_statement", node, src)?;

        let query_str = r#"
            (call_expression
              function: (identifier) @func (#eq? @func "DEPRECATED_FUNC")
              arguments: (argument_list
                (string_literal (string_content) @content)
              )
            )
        "#;

        let mut query_cursor = QueryCursor::new();
        let language = tree_sitter_c::LANGUAGE;
        let query = Query::new(&language.into(), query_str)?;

        let captures = query_cursor.captures(&query, node, src);
        for (mat, _) in captures {
            for capture in mat.captures {
                if query.capture_names()[capture.index as usize] == "content" {
                    return Ok(Self(node_text(capture.node, src)));
                }
            }
        }

        Err(node_error("DEPRECATED_FUNC call not found or malformed", node, src).into())
    }
}

fn process_typedef_item(
    mut metadata: ItemMetadata,
    item: Node,
    src: &[u8],
) -> Result<Item, Box<dyn Error>> {
    require_kind("type_definition", item, src)?;

    let typedef_node = item.child_by_field_name("type").unwrap();
    let typedef_kind = typedef_node.kind();

    // We allow an uncommented type_definition if the previous node was a bare enum_specifier.
    // This happens when an enum has a primitive type repr, like rustls_result. The enum
    // appears without typedef (but with comment), and then a typedef uint32_t appears (without
    // preceding comment). This is OK and doesn't count as an undocumented error.
    //
    // It's important we use prev_named_sibling() for finding the enum_specifier that precedes
    // the typedef. Using prev_sibling() would return an anonymous ';' node.
    match (metadata.comment.is_none(), item.prev_named_sibling()) {
        (true, Some(sib)) if sib.kind() == "enum_specifier" => {
            metadata.comment = Some(Comment::default());
        }
        _ => require_documented(&metadata, item, src)?,
    }

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
        "enum_specifier" => Item::from(EnumItem::new(metadata, typedef_node, src)?),

        // e.g. `typedef uint32_t (*rustls_verify_server_cert_callback)(...);`
        "primitive_type" if func_declarator => Item::from(CallbackItem::new(metadata, item, src)?),

        // e.g. `typedef rustls_io_result (*rustls_read_callback)(...);`
        "type_identifier" if func_declarator => Item::from(CallbackItem::new(metadata, item, src)?),

        // e.g. `typedef const struct rustls_certified_key *(*rustls_client_hello_callback)(...);`
        "struct_specifier" if func_declarator => {
            Item::from(CallbackItem::new(metadata, item, src)?)
        }

        // e.g. `typedef struct rustls_accepted rustls_accepted;`
        "struct_specifier" => Item::from(StructItem::new(metadata, typedef_node, src)?),

        // e.g. `typedef int rustls_io_result;`
        "primitive_type" if !func_declarator => Item::from(TypeAliasItem::new(metadata, item, src)),

        // e.g. ... well, none so far - but something like `typedef rustls_io_result rustls_funtime_io_result;`.
        "type_identifier" if !func_declarator => {
            Item::from(TypeAliasItem::new(metadata, item, src))
        }

        _ => return Err(format!("unknown typedef kind: {typedef_kind:?}").into()),
    })
}

fn process_declaration_item(
    metadata: ItemMetadata,
    item: Node,
    src: &[u8],
) -> Result<Item, Box<dyn Error>> {
    require_kind("declaration", item, src)?;
    require_documented(&metadata, item, src)?;

    if item.child(0).unwrap().kind() == "storage_class_specifier" {
        // extern is a storage_class_specifier.
        Ok(Item::from(ExternItem::new(metadata, item, src)?))
    } else {
        // other non-extern declarations are functions.
        Ok(Item::from(FunctionItem::new(metadata, item, src)?))
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

impl Item {
    fn anchor(&self) -> &str {
        match self {
            Item::Enum(item) => &item.anchor,
            Item::Struct(item) => &item.anchor,
            Item::TypeAlias(item) => &item.anchor,
            Item::Callback(item) => &item.anchor,
            Item::Function(item) => &item.anchor,
            Item::Extern(item) => &item.anchor,
        }
    }

    fn crosslink(&mut self, anchors: &HashSet<String>) -> Result<(), Box<dyn Error>> {
        let metadata = match self {
            Item::Enum(item) => &mut item.metadata,
            Item::Struct(item) => &mut item.metadata,
            Item::TypeAlias(item) => &mut item.metadata,
            Item::Callback(item) => &mut item.metadata,
            Item::Function(item) => &mut item.metadata,
            Item::Extern(item) => &mut item.metadata,
        };
        metadata.crosslink(anchors)
    }
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
    #[serde(flatten)]
    metadata: ItemMetadata,
    name: String,
    variants: Vec<EnumVariantItem>,
}

impl EnumItem {
    fn new(metadata: ItemMetadata, enum_spec: Node, src: &[u8]) -> Result<Self, Box<dyn Error>> {
        require_documented(&metadata, enum_spec, src)?;

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
            metadata,
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
    #[serde(flatten)]
    metadata: ItemMetadata,
    name: String,
    text: String,
}

impl StructItem {
    fn new(metadata: ItemMetadata, struct_node: Node, src: &[u8]) -> Result<Self, Box<dyn Error>> {
        require_kind("struct_specifier", struct_node, src)?;

        let name = node_text(struct_node.child_by_field_name("name").unwrap(), src);
        Ok(Self {
            anchor: name.replace('_', "-").to_ascii_lowercase(),
            metadata,
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
    #[serde(flatten)]
    metadata: ItemMetadata,
    name: String,
    text: String,
}

impl TypeAliasItem {
    fn new(metadata: ItemMetadata, item: Node, src: &[u8]) -> Self {
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
            metadata,
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
    #[serde(flatten)]
    metadata: ItemMetadata,
    name: String,
    text: String,
}

impl CallbackItem {
    fn new(metadata: ItemMetadata, typedef: Node, src: &[u8]) -> Result<Self, Box<dyn Error>> {
        require_kind("type_definition", typedef, src)?;

        let name = function_identifier(typedef, src);
        Ok(Self {
            anchor: name.replace("_'", "-").to_ascii_lowercase(),
            metadata,
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
    #[serde(flatten)]
    metadata: ItemMetadata,
    name: String,
    text: String,
}

impl FunctionItem {
    fn new(metadata: ItemMetadata, decl_node: Node, src: &[u8]) -> Result<Self, Box<dyn Error>> {
        require_kind("declaration", decl_node, src)?;

        let name = function_identifier(decl_node, src);
        Ok(Self {
            anchor: name.replace('_', "-").to_ascii_lowercase(),
            metadata,
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
    #[serde(flatten)]
    metadata: ItemMetadata,
    name: String,
    text: String,
}

impl ExternItem {
    fn new(metadata: ItemMetadata, decl_node: Node, src: &[u8]) -> Result<Self, Box<dyn Error>> {
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
            metadata,
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

/// Return an error if `ItemMetadat` doesn't contain a `Comment`
///
/// The error will describe the kind of node that was missing a documentation comment, as well
/// as its location (line/col) in the source code.
fn require_documented(
    metadata: &ItemMetadata,
    item: Node,
    src: &[u8],
) -> Result<(), Box<dyn Error>> {
    if metadata.comment.is_none() {
        return Err(node_error(
            format!("undocumented {kind}", kind = item.kind()),
            item,
            src,
        )
        .into());
    }
    Ok(())
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
