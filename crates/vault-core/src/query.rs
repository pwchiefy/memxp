//! Fuzzy search engine for vault entries.
//!
//! Provides tokenization, synonym expansion, Levenshtein scoring,
//! and multi-factor ranking for smart_get queries.

use std::collections::HashMap;
use strsim::levenshtein;

use crate::models::VaultEntry;

/// Tokenize a path/query string into searchable tokens.
///
/// `"api/openai/prod-key"` → `["api", "openai", "prod", "key"]`
pub fn tokenize(input: &str) -> Vec<String> {
    input
        .to_lowercase()
        .split(|c: char| c == '/' || c == '-' || c == '_' || c == '.' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Normalize a string for comparison (lowercase, strip separators).
pub fn normalize(input: &str) -> String {
    input
        .to_lowercase()
        .replace(['/', '-', '_', '.'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Synonym maps for environment, category, and service terms.
pub struct SynonymMaps {
    pub env: HashMap<String, Vec<String>>,
    pub category: HashMap<String, Vec<String>>,
    pub service: HashMap<String, Vec<String>>,
}

impl Default for SynonymMaps {
    fn default() -> Self {
        Self::new()
    }
}

impl SynonymMaps {
    pub fn new() -> Self {
        let mut env = HashMap::new();
        env.insert(
            "prod".into(),
            vec!["production".into(), "prd".into(), "live".into()],
        );
        env.insert(
            "dev".into(),
            vec!["development".into(), "local".into(), "devel".into()],
        );
        env.insert(
            "stg".into(),
            vec!["staging".into(), "stage".into(), "preprod".into()],
        );
        env.insert(
            "test".into(),
            vec!["testing".into(), "qa".into(), "uat".into()],
        );

        let mut category = HashMap::new();
        category.insert(
            "key".into(),
            vec![
                "api_key".into(),
                "apikey".into(),
                "token".into(),
                "secret".into(),
            ],
        );
        category.insert(
            "pass".into(),
            vec![
                "password".into(),
                "passwd".into(),
                "pwd".into(),
                "secret".into(),
            ],
        );
        category.insert(
            "cert".into(),
            vec!["certificate".into(), "ssl".into(), "tls".into()],
        );
        category.insert(
            "db".into(),
            vec![
                "database".into(),
                "postgres".into(),
                "mysql".into(),
                "sql".into(),
            ],
        );

        let mut service = HashMap::new();
        service.insert(
            "aws".into(),
            vec!["amazon".into(), "s3".into(), "ec2".into(), "lambda".into()],
        );
        service.insert("gcp".into(), vec!["google".into(), "gcloud".into()]);
        service.insert("github".into(), vec!["gh".into(), "git".into()]);
        service.insert(
            "postgres".into(),
            vec!["pg".into(), "postgresql".into(), "psql".into()],
        );
        service.insert("kubernetes".into(), vec!["k8s".into(), "kube".into()]);

        Self {
            env,
            category,
            service,
        }
    }

    /// Check if two tokens are synonyms.
    pub fn are_synonyms(&self, a: &str, b: &str) -> bool {
        let a = a.to_lowercase();
        let b = b.to_lowercase();

        if a == b {
            return true;
        }

        for map in [&self.env, &self.category, &self.service] {
            // Check if a is a key and b is in its synonyms
            if let Some(syns) = map.get(&a) {
                if syns.iter().any(|s| s == &b) {
                    return true;
                }
            }
            // Check if b is a key and a is in its synonyms
            if let Some(syns) = map.get(&b) {
                if syns.iter().any(|s| s == &a) {
                    return true;
                }
            }
            // Check if both are in the same synonym group
            for (key, syns) in map {
                let a_match = key == &a || syns.iter().any(|s| s == &a);
                let b_match = key == &b || syns.iter().any(|s| s == &b);
                if a_match && b_match {
                    return true;
                }
            }
        }

        false
    }
}

/// A scored search match.
#[derive(Debug, Clone)]
pub struct SearchMatch {
    pub entry: VaultEntry,
    pub score: f64,
    pub confidence: f64, // 0-100
}

/// Score and rank entries against a query.
///
/// Returns matches sorted by score (highest first).
pub fn rank_matches(query: &str, entries: &[VaultEntry], max_results: usize) -> Vec<SearchMatch> {
    let synonyms = SynonymMaps::new();
    let query_tokens = tokenize(query);

    if query_tokens.is_empty() {
        return Vec::new();
    }

    let mut scored: Vec<SearchMatch> = entries
        .iter()
        .map(|entry| {
            let score = compute_score(entry, &query_tokens, &synonyms);
            SearchMatch {
                entry: entry.clone(),
                score,
                confidence: (score * 100.0).min(100.0),
            }
        })
        .filter(|m| m.score > 0.0)
        .collect();

    scored.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    scored.truncate(max_results);

    // Normalize confidence relative to best score
    if let Some(best) = scored.first().map(|m| m.score) {
        if best > 0.0 {
            for m in &mut scored {
                m.confidence = (m.score / best * 100.0).round();
            }
        }
    }

    scored
}

/// Compute a relevance score for an entry against query tokens.
fn compute_score(entry: &VaultEntry, query_tokens: &[String], synonyms: &SynonymMaps) -> f64 {
    let path_tokens = tokenize(&entry.path);
    let notes_tokens = entry.notes.as_deref().map(tokenize).unwrap_or_default();
    let tags_tokens: Vec<String> = entry.tags.iter().flat_map(|t| tokenize(t)).collect();
    let service_tokens = entry.service.as_deref().map(tokenize).unwrap_or_default();
    let category_tokens = tokenize(&entry.category);

    let mut score = 0.0;
    let mut matched_query_tokens = 0;

    for qt in query_tokens {
        let mut best_token_score = 0.0f64;

        // Exact match in path (highest weight)
        if path_tokens.iter().any(|pt| pt == qt) {
            best_token_score = best_token_score.max(10.0);
        }

        // Exact match in service
        if service_tokens.iter().any(|st| st == qt) {
            best_token_score = best_token_score.max(8.0);
        }

        // Exact match in category
        if category_tokens.iter().any(|ct| ct == qt) {
            best_token_score = best_token_score.max(6.0);
        }

        // Exact match in tags
        if tags_tokens.iter().any(|tt| tt == qt) {
            best_token_score = best_token_score.max(5.0);
        }

        // Exact match in notes
        if notes_tokens.iter().any(|nt| nt == qt) {
            best_token_score = best_token_score.max(3.0);
        }

        // Synonym match in path
        if path_tokens.iter().any(|pt| synonyms.are_synonyms(pt, qt)) {
            best_token_score = best_token_score.max(7.0);
        }

        // Synonym match in service
        if service_tokens
            .iter()
            .any(|st| synonyms.are_synonyms(st, qt))
        {
            best_token_score = best_token_score.max(6.0);
        }

        // Substring match in path
        if entry.path.to_lowercase().contains(&qt.to_lowercase()) {
            best_token_score = best_token_score.max(4.0);
        }

        // Levenshtein match in path tokens (fuzzy)
        for pt in &path_tokens {
            if pt.len() > 2 && qt.len() > 2 {
                let dist = levenshtein(pt, qt);
                let max_len = pt.len().max(qt.len());
                if dist <= 2 && dist < max_len {
                    let fuzzy_score = 3.0 * (1.0 - dist as f64 / max_len as f64);
                    best_token_score = best_token_score.max(fuzzy_score);
                }
            }
        }

        if best_token_score > 0.0 {
            matched_query_tokens += 1;
        }
        score += best_token_score;
    }

    // Bonus for matching all query tokens
    if matched_query_tokens == query_tokens.len() && query_tokens.len() > 1 {
        score *= 1.5;
    }

    // Penalty for unmatched query tokens
    let match_ratio = matched_query_tokens as f64 / query_tokens.len() as f64;
    score *= match_ratio;

    score
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_tokenize() {
        let tokens = tokenize("api/openai/prod-key");
        assert_eq!(tokens, vec!["api", "openai", "prod", "key"]);

        let tokens2 = tokenize("postgres_prod.password");
        assert_eq!(tokens2, vec!["postgres", "prod", "password"]);

        let tokens3 = tokenize("  hello   world  ");
        assert_eq!(tokens3, vec!["hello", "world"]);
    }

    #[test]
    fn test_query_synonyms() {
        let syns = SynonymMaps::new();

        // Environment synonyms
        assert!(syns.are_synonyms("prod", "production"));
        assert!(syns.are_synonyms("production", "prod"));
        assert!(syns.are_synonyms("dev", "development"));

        // Service synonyms
        assert!(syns.are_synonyms("pg", "postgres"));
        assert!(syns.are_synonyms("postgres", "postgresql"));
        assert!(syns.are_synonyms("k8s", "kubernetes"));
        assert!(syns.are_synonyms("gh", "github"));

        // Category synonyms
        assert!(syns.are_synonyms("pass", "password"));

        // Non-synonyms
        assert!(!syns.are_synonyms("prod", "password"));
        assert!(!syns.are_synonyms("openai", "postgres"));
    }

    #[test]
    fn test_query_rank_matches() {
        let entries = vec![
            VaultEntry {
                path: "api/openai/key".into(),
                value: "sk-xxx".into(),
                category: "api_key".into(),
                service: Some("openai".into()),
                ..VaultEntry::new("", "")
            },
            VaultEntry {
                path: "api/anthropic/key".into(),
                value: "sk-yyy".into(),
                category: "api_key".into(),
                service: Some("anthropic".into()),
                ..VaultEntry::new("", "")
            },
            VaultEntry {
                path: "db/postgres/prod/password".into(),
                value: "pg-pass".into(),
                category: "password".into(),
                service: Some("postgres".into()),
                ..VaultEntry::new("", "")
            },
        ];

        // Search for "openai" should rank openai entry highest
        let results = rank_matches("openai", &entries, 10);
        assert!(!results.is_empty());
        assert_eq!(results[0].entry.path, "api/openai/key");
        assert_eq!(results[0].confidence, 100.0);

        // Search for "postgres" should rank postgres entry highest
        let results2 = rank_matches("postgres", &entries, 10);
        assert!(!results2.is_empty());
        assert_eq!(results2[0].entry.path, "db/postgres/prod/password");

        // Search for "pg" should match postgres via synonym
        let results3 = rank_matches("pg", &entries, 10);
        assert!(!results3.is_empty());
        assert_eq!(results3[0].entry.path, "db/postgres/prod/password");
    }
}
