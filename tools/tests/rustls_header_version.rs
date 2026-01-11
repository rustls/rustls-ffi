use std::fs::File;
use std::fs::read_to_string;
use std::io::Read;
use std::path::PathBuf;

use toml::Table;
use tree_sitter::{Parser, Query, QueryCursor, StreamingIterator};

/// Ensure that the correct version part defines are in src/rustls.h
///
/// If this test starts to fail, you probably forgot to update cbindgen.toml with new version
/// parts, or need to rerun cbindgen after updating it.
///
/// This test is in the tools crate because it requires an msrv of 1.76 and the librustls crate
/// currently has an msrv of 1.73.
#[test]
fn rustls_header_versions_match() {
    // Parse Cargo.toml as a generic TOML Table.
    let mut metadata_file =
        File::open(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../librustls/Cargo.toml"))
            .expect("failed to open Cargo.toml");
    let mut metadata_content = String::new();
    metadata_file
        .read_to_string(&mut metadata_content)
        .expect("failed to read Cargo.toml");
    let metadata = metadata_content.parse::<Table>().unwrap();

    // Find the crate version specified in Cargo.toml
    let package_metadata = metadata["package"]
        .as_table()
        .expect("missing package metadata");
    let crate_version = package_metadata["version"]
        .as_str()
        .expect("missing crate version");

    let version_in_header = version_in_header();
    assert_eq!(
        crate_version, version_in_header,
        "Version in header (.h file) doesn't match version in Cargo.toml"
    );
}

fn version_in_header() -> String {
    // Create a C parser.
    let mut parser = Parser::new();
    let language = tree_sitter_c::LANGUAGE;
    parser.set_language(&language.into()).unwrap();

    // Parse the .h into an AST.
    let header_file =
        read_to_string("../librustls/src/rustls.h").expect("Couldn't read header file");

    let header_file_bytes = header_file.as_bytes();
    let tree = parser
        .parse(&header_file, None)
        .ok_or("no tree parsed from input")
        .unwrap();
    let query = r#"
        (preproc_def name: (identifier) @define.name
            (#match? @define.name "^RUSTLS_VERSION_[MAJOR|MINOR|PATCH]")
        )"#;
    let query = Query::new(&language.into(), query).unwrap();
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, tree.root_node(), header_file_bytes);
    let mut version_parts: [&str; 3] = Default::default();
    loop {
        matches.advance();
        let Some(query_match) = matches.get() else {
            break;
        };

        for preproc in query_match.nodes_for_capture_index(0) {
            let Some(value_node) = preproc.parent().unwrap().child_by_field_name("value") else {
                continue;
            };
            let key = preproc.utf8_text(header_file_bytes).unwrap();
            let value = value_node.utf8_text(header_file_bytes).unwrap();
            match key {
                "RUSTLS_VERSION_MAJOR" => {
                    version_parts[0] = value;
                }
                "RUSTLS_VERSION_MINOR" => {
                    version_parts[1] = value;
                }
                "RUSTLS_VERSION_PATCH" => {
                    version_parts[2] = value;
                }
                _ => (),
            }
        }
    }
    format!(
        "{0}.{1}.{2}",
        version_parts[0], version_parts[1], version_parts[2]
    )
}
