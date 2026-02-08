//! Jupyter Notebook (`.ipynb`) text extractor.
//!
//! Parses the JSON structure of a notebook and extracts source lines from
//! **all** cell types — code, markdown, and raw. Markdown cells are included
//! because they frequently contain embedded secrets in code fences, inline
//! snippets, or configuration examples.
//!
//! # Format
//!
//! A `.ipynb` file is JSON with the shape:
//! ```json
//! {
//!   "cells": [
//!     {
//!       "cell_type": "code",
//!       "source": ["line1\n", "line2\n"]
//!     }
//!   ]
//! }
//! ```
//!
//! # Extraction strategy
//!
//! - Each cell's `source` array is concatenated verbatim (lines already
//!   contain their own `\n` terminators).
//! - A trailing `\n` is appended after each non-empty cell to ensure
//!   cell boundaries are visible to line-oriented scan rules.
//! - Output blobs (`outputs` key) are deliberately ignored — they are
//!   large, noisy, and rarely contain secrets.
//! - Cells without a `source` key are silently skipped.

use super::extract::{ExtractResult, Extractor};

/// Extracts source text from all cell types in a Jupyter Notebook.
pub struct IpynbExtractor;

impl Extractor for IpynbExtractor {
    fn extract(&self, data: &[u8], out: &mut Vec<u8>) -> ExtractResult {
        let parsed: serde_json::Value = match serde_json::from_slice(data) {
            Ok(v) => v,
            Err(_) => return ExtractResult::ParseError,
        };

        let cells = match parsed.get("cells").and_then(|c| c.as_array()) {
            Some(arr) => arr,
            None => return ExtractResult::Empty,
        };

        let start_len = out.len();

        for cell in cells {
            let source = match cell.get("source").and_then(|s| s.as_array()) {
                Some(arr) => arr,
                None => continue,
            };
            for line in source {
                if let Some(s) = line.as_str() {
                    out.extend_from_slice(s.as_bytes());
                }
            }
            // Separate cells with a newline.
            if !source.is_empty() {
                out.push(b'\n');
            }
        }

        if out.len() == start_len {
            ExtractResult::Empty
        } else {
            ExtractResult::Ok
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_code_cell_source() {
        let notebook = r##"{
            "cells": [
                {
                    "cell_type": "code",
                    "source": ["import os\n", "SECRET_KEY = 'abc123'\n"]
                }
            ]
        }"##;
        let mut out = Vec::new();
        let result = IpynbExtractor.extract(notebook.as_bytes(), &mut out);
        assert_eq!(result, ExtractResult::Ok);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("SECRET_KEY"));
        assert!(text.contains("import os"));
    }

    #[test]
    fn extracts_multiple_cells() {
        let notebook = r##"{
            "cells": [
                {
                    "cell_type": "code",
                    "source": ["x = 1\n"]
                },
                {
                    "cell_type": "markdown",
                    "source": ["# Title\n"]
                },
                {
                    "cell_type": "code",
                    "source": ["password = 'hunter2'\n"]
                }
            ]
        }"##;
        let mut out = Vec::new();
        let result = IpynbExtractor.extract(notebook.as_bytes(), &mut out);
        assert_eq!(result, ExtractResult::Ok);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("x = 1"));
        assert!(text.contains("# Title"));
        assert!(text.contains("password"));
    }

    #[test]
    fn empty_cells_returns_empty() {
        let notebook = r#"{"cells": []}"#;
        let mut out = Vec::new();
        assert_eq!(
            IpynbExtractor.extract(notebook.as_bytes(), &mut out),
            ExtractResult::Empty
        );
    }

    #[test]
    fn no_cells_key_returns_empty() {
        let data = r#"{"metadata": {}}"#;
        let mut out = Vec::new();
        assert_eq!(
            IpynbExtractor.extract(data.as_bytes(), &mut out),
            ExtractResult::Empty
        );
    }

    #[test]
    fn invalid_json_returns_parse_error() {
        let mut out = Vec::new();
        assert_eq!(
            IpynbExtractor.extract(b"not json", &mut out),
            ExtractResult::ParseError
        );
    }

    #[test]
    fn cells_without_source_skipped() {
        let notebook = r##"{
            "cells": [
                {"cell_type": "raw"},
                {"cell_type": "code", "source": ["found\n"]}
            ]
        }"##;
        let mut out = Vec::new();
        let result = IpynbExtractor.extract(notebook.as_bytes(), &mut out);
        assert_eq!(result, ExtractResult::Ok);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("found"));
    }
}
