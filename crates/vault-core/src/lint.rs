//! Path hygiene analysis for vault entries.
//!
//! Detects duplicates, similar paths, naming issues, and suggests
//! canonical path forms.

use std::collections::HashMap;
use strsim::normalized_levenshtein;

/// A group of duplicate paths (case-insensitive).
#[derive(Debug, Clone)]
pub struct DuplicateGroup {
    pub canonical: String,
    pub paths: Vec<String>,
}

/// A pair of similar paths that might be duplicates.
#[derive(Debug, Clone)]
pub struct SimilarPair {
    pub path_a: String,
    pub path_b: String,
    pub similarity: f64,
}

/// A suggestion for improving a path name.
#[derive(Debug, Clone)]
pub struct PathSuggestion {
    pub path: String,
    pub suggested: String,
    pub issues: Vec<String>,
}

/// Complete lint results.
#[derive(Debug, Clone)]
pub struct LintResult {
    pub duplicates: Vec<DuplicateGroup>,
    pub similar_pairs: Vec<SimilarPair>,
    pub suggestions: Vec<PathSuggestion>,
    pub total_paths: usize,
}

/// Run lint analysis on a set of paths.
pub fn lint_paths(
    paths: &[String],
    similarity_threshold: f64,
    max_similar_pairs: usize,
) -> LintResult {
    let total_paths = paths.len();

    // 1. Detect case-insensitive duplicates
    let duplicates = find_duplicates(paths);

    // 2. Find similar pairs (Levenshtein)
    let similar_pairs = find_similar_pairs(paths, similarity_threshold, max_similar_pairs);

    // 3. Generate canonical suggestions
    let suggestions = generate_suggestions(paths);

    LintResult {
        duplicates,
        similar_pairs,
        suggestions,
        total_paths,
    }
}

/// Find case-insensitive duplicate paths.
fn find_duplicates(paths: &[String]) -> Vec<DuplicateGroup> {
    let mut groups: HashMap<String, Vec<String>> = HashMap::new();

    for path in paths {
        let key = path.to_lowercase();
        groups.entry(key).or_default().push(path.clone());
    }

    groups
        .into_iter()
        .filter(|(_, paths)| paths.len() > 1)
        .map(|(canonical, paths)| DuplicateGroup { canonical, paths })
        .collect()
}

/// Find pairs of similar paths using normalized Levenshtein distance.
fn find_similar_pairs(paths: &[String], threshold: f64, max_pairs: usize) -> Vec<SimilarPair> {
    let mut pairs = Vec::new();
    let normalized: Vec<String> = paths.iter().map(|p| p.to_lowercase()).collect();

    for i in 0..normalized.len() {
        for j in (i + 1)..normalized.len() {
            // Skip if they're case-insensitive duplicates (handled separately)
            if normalized[i] == normalized[j] {
                continue;
            }

            let similarity = normalized_levenshtein(&normalized[i], &normalized[j]);
            if similarity >= threshold && similarity < 1.0 {
                pairs.push(SimilarPair {
                    path_a: paths[i].clone(),
                    path_b: paths[j].clone(),
                    similarity,
                });
            }

            if pairs.len() >= max_pairs {
                return pairs;
            }
        }
    }

    pairs.sort_by(|a, b| {
        b.similarity
            .partial_cmp(&a.similarity)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    pairs
}

/// Generate canonical path suggestions.
fn generate_suggestions(paths: &[String]) -> Vec<PathSuggestion> {
    let mut suggestions = Vec::new();

    for path in paths {
        let mut issues = Vec::new();
        let mut suggested = path.clone();

        // Check for uppercase characters
        if path != &path.to_lowercase() {
            issues.push("contains uppercase characters".into());
            suggested = path.to_lowercase();
        }

        // Check for double separators
        if path.contains("//") || path.contains("--") || path.contains("__") {
            issues.push("contains double separators".into());
            suggested = suggested
                .replace("//", "/")
                .replace("--", "-")
                .replace("__", "_");
        }

        // Check for trailing separator
        if path.ends_with('/') || path.ends_with('-') || path.ends_with('_') {
            issues.push("trailing separator".into());
            suggested = suggested.trim_end_matches(['/', '-', '_']).to_string();
        }

        // Check for leading separator
        if path.starts_with('/') {
            issues.push("leading separator".into());
            suggested = suggested.trim_start_matches('/').to_string();
        }

        // Check for spaces
        if path.contains(' ') {
            issues.push("contains spaces".into());
            suggested = suggested.replace(' ', "-");
        }

        // Check for mixed separators within segments
        let segments: Vec<&str> = path.split('/').collect();
        for seg in &segments {
            if seg.contains('-') && seg.contains('_') {
                issues.push("mixed separators in segment".into());
                break;
            }
        }

        if !issues.is_empty() {
            suggestions.push(PathSuggestion {
                path: path.clone(),
                suggested,
                issues,
            });
        }
    }

    suggestions
}

/// Format lint results as a human-readable report.
pub fn format_lint_report(result: &LintResult) -> String {
    let mut lines = Vec::new();

    lines.push(format!(
        "Vault Path Lint Report ({} paths analyzed)",
        result.total_paths
    ));
    lines.push("=".repeat(50));

    if !result.duplicates.is_empty() {
        lines.push(format!("\nDuplicates ({}):", result.duplicates.len()));
        for dup in &result.duplicates {
            lines.push(format!(
                "  {} paths → canonical: {}",
                dup.paths.len(),
                dup.canonical
            ));
            for p in &dup.paths {
                lines.push(format!("    - {p}"));
            }
        }
    }

    if !result.similar_pairs.is_empty() {
        lines.push(format!("\nSimilar Pairs ({}):", result.similar_pairs.len()));
        for pair in &result.similar_pairs {
            lines.push(format!(
                "  {:.0}% similar: {} ↔ {}",
                pair.similarity * 100.0,
                pair.path_a,
                pair.path_b
            ));
        }
    }

    if !result.suggestions.is_empty() {
        lines.push(format!("\nSuggestions ({}):", result.suggestions.len()));
        for sugg in &result.suggestions {
            lines.push(format!("  {} → {}", sugg.path, sugg.suggested));
            for issue in &sugg.issues {
                lines.push(format!("    * {issue}"));
            }
        }
    }

    if result.duplicates.is_empty()
        && result.similar_pairs.is_empty()
        && result.suggestions.is_empty()
    {
        lines.push("  No issues found!".into());
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lint_detects_duplicates() {
        let paths = vec![
            "api/openai/key".to_string(),
            "API/OpenAI/Key".to_string(),
            "db/postgres/pass".to_string(),
        ];

        let result = lint_paths(&paths, 0.7, 20);
        assert_eq!(result.duplicates.len(), 1);
        assert_eq!(result.duplicates[0].paths.len(), 2);
    }

    #[test]
    fn test_lint_suggests_canonical() {
        let paths = vec![
            "API/OpenAI/Key".to_string(),
            "api//double/sep".to_string(),
            "/leading/slash".to_string(),
            "trailing/slash/".to_string(),
            "has spaces/here".to_string(),
        ];

        let result = lint_paths(&paths, 0.7, 20);
        assert!(!result.suggestions.is_empty());

        // Check uppercase suggestion
        let uppercase = result
            .suggestions
            .iter()
            .find(|s| s.path == "API/OpenAI/Key");
        assert!(uppercase.is_some());
        assert_eq!(uppercase.unwrap().suggested, "api/openai/key");

        // Check double separator
        let double = result
            .suggestions
            .iter()
            .find(|s| s.path == "api//double/sep");
        assert!(double.is_some());
        assert_eq!(double.unwrap().suggested, "api/double/sep");

        // Check leading slash
        let leading = result
            .suggestions
            .iter()
            .find(|s| s.path == "/leading/slash");
        assert!(leading.is_some());
        assert_eq!(leading.unwrap().suggested, "leading/slash");
    }

    #[test]
    fn test_lint_similar_pairs() {
        let paths = vec![
            "api/openai/key".to_string(),
            "api/openai/keys".to_string(), // very similar
            "db/postgres/pass".to_string(),
        ];

        let result = lint_paths(&paths, 0.7, 20);
        assert!(!result.similar_pairs.is_empty());
        let pair = &result.similar_pairs[0];
        assert!(pair.similarity > 0.7);
    }
}
