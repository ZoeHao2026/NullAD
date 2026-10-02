//! Label-reversed domain trie for `||domain^` anchor rules.
//!
//! Domain anchors make up the overwhelming majority of real filter lists, so
//! they get a dedicated index whose cost is proportional to the number of
//! labels in the request host — not to the number of rules. A 500k-rule list
//! answers a host lookup in a handful of hash probes.
//!
//! Domains are stored reversed by label (`ads.example.com` is walked as
//! `com` → `example` → `ads`) so that a lookup walks from the public suffix
//! inward and can collect every matching suffix on the way.

use hashbrown::HashMap;
use smallvec::SmallVec;

/// A node in the label-reversed trie.
#[derive(Debug, Default)]
struct Node {
    /// Child labels, keyed by their lowercase text.
    children: HashMap<Box<str>, u32>,
    /// Rule ids whose domain ends exactly at this node.
    rules: SmallVec<[u32; 2]>,
}

/// An index of rules keyed by domain suffix.
#[derive(Debug, Default)]
pub struct DomainTrie {
    nodes: Vec<Node>,
    /// Number of rules stored.
    len: usize,
}

impl DomainTrie {
    /// Creates an empty trie.
    #[must_use]
    pub fn new() -> Self {
        let mut nodes = Vec::with_capacity(1);
        nodes.push(Node::default());
        Self { nodes, len: 0 }
    }

    /// Creates an empty trie with pre-allocated node capacity.
    #[must_use]
    pub fn with_capacity(nodes: usize) -> Self {
        let mut storage = Vec::with_capacity(nodes.max(1));
        storage.push(Node::default());
        Self {
            nodes: storage,
            len: 0,
        }
    }

    /// Returns the number of indexed rules.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` when no rules are indexed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Number of allocated trie nodes, for diagnostics.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Inserts a domain and associates it with a rule id.
    ///
    /// The domain must already be lowercase ASCII (the parser normalises it).
    pub fn insert(&mut self, domain: &str, rule_id: u32) {
        if domain.is_empty() {
            return;
        }

        let mut node = 0u32;
        for label in domain.rsplit('.') {
            if label.is_empty() {
                // A leading dot or a double dot: skip rather than corrupt the
                // index. The parser rejects these, but the index is defensive.
                continue;
            }
            let next = match self.nodes[node as usize].children.get(label) {
                Some(&existing) => existing,
                None => {
                    let created = u32::try_from(self.nodes.len()).unwrap_or(u32::MAX);
                    if created == u32::MAX {
                        return;
                    }
                    self.nodes.push(Node::default());
                    self.nodes[node as usize]
                        .children
                        .insert(label.into(), created);
                    created
                }
            };
            node = next;
        }

        self.nodes[node as usize].rules.push(rule_id);
        self.len += 1;
    }

    /// Collects every rule id whose domain is a suffix of `host`.
    ///
    /// Matching is on label boundaries, so `nota.com` does not match `a.com`.
    /// The host must be lowercase ASCII.
    pub fn lookup(&self, host: &str, out: &mut Vec<u32>) {
        if host.is_empty() || self.len == 0 {
            return;
        }

        let mut node = 0u32;
        for label in host.rsplit('.') {
            if label.is_empty() {
                continue;
            }
            let Some(&next) = self.nodes[node as usize].children.get(label) else {
                return;
            };
            node = next;
            let rules = &self.nodes[node as usize].rules;
            if !rules.is_empty() {
                out.extend_from_slice(rules);
            }
        }
    }

    /// Returns `true` when `host` is covered by at least one rule.
    #[must_use]
    pub fn contains_host(&self, host: &str) -> bool {
        let mut scratch = Vec::new();
        self.lookup(host, &mut scratch);
        !scratch.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup_sorted(trie: &DomainTrie, host: &str) -> Vec<u32> {
        let mut out = Vec::new();
        trie.lookup(host, &mut out);
        out.sort_unstable();
        out
    }

    #[test]
    fn matches_exact_domain() {
        let mut trie = DomainTrie::new();
        trie.insert("example.com", 1);
        assert_eq!(lookup_sorted(&trie, "example.com"), vec![1]);
    }

    #[test]
    fn matches_subdomains() {
        let mut trie = DomainTrie::new();
        trie.insert("example.com", 1);
        assert_eq!(lookup_sorted(&trie, "ads.example.com"), vec![1]);
        assert_eq!(lookup_sorted(&trie, "a.b.c.example.com"), vec![1]);
    }

    #[test]
    fn does_not_match_partial_labels() {
        let mut trie = DomainTrie::new();
        trie.insert("a.com", 1);
        assert!(lookup_sorted(&trie, "nota.com").is_empty());
        assert!(lookup_sorted(&trie, "x-a.com").is_empty());
        assert!(lookup_sorted(&trie, "a.com.evil.net").is_empty());
    }

    #[test]
    fn collects_all_matching_suffixes() {
        let mut trie = DomainTrie::new();
        trie.insert("com", 1);
        trie.insert("example.com", 2);
        trie.insert("ads.example.com", 3);
        assert_eq!(lookup_sorted(&trie, "ads.example.com"), vec![1, 2, 3]);
        assert_eq!(lookup_sorted(&trie, "example.com"), vec![1, 2]);
        assert_eq!(lookup_sorted(&trie, "other.com"), vec![1]);
    }

    #[test]
    fn multiple_rules_on_same_domain() {
        let mut trie = DomainTrie::new();
        trie.insert("ads.com", 7);
        trie.insert("ads.com", 9);
        assert_eq!(lookup_sorted(&trie, "ads.com"), vec![7, 9]);
        assert_eq!(trie.len(), 2);
    }

    #[test]
    fn empty_and_edge_inputs_are_safe() {
        let mut trie = DomainTrie::new();
        assert!(trie.is_empty());
        trie.insert("", 1);
        assert!(trie.is_empty());
        trie.insert("example.com", 1);
        assert!(lookup_sorted(&trie, "").is_empty());
        assert_eq!(lookup_sorted(&trie, "example.com"), vec![1]);
        // Root + "com" + "example".
        assert_eq!(trie.node_count(), 3);
    }
}
