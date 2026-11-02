// Small on-chain blocklist for scam domains and account ids.
// The owner adds/removes entries, anyone can read them for free with a view call.
use near_sdk::store::IterableSet;
use near_sdk::{env, near, require, AccountId, PanicOnDefault};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Blocklist {
    owner: AccountId,
    entries: IterableSet<String>,
}

// lowercase + trim so "Evil.xyz " and "evil.xyz" are the same entry
fn norm(v: &str) -> String {
    v.trim().to_lowercase()
}

#[near]
impl Blocklist {
    #[init]
    pub fn new(owner: AccountId) -> Self {
        Self { owner, entries: IterableSet::new(b"e") }
    }

    fn only_owner(&self) {
        require!(env::predecessor_account_id() == self.owner, "only the owner can change the list");
    }

    pub fn add(&mut self, values: Vec<String>) -> u32 {
        self.only_owner();
        let mut added = 0;
        for v in values {
            let v = norm(&v);
            if !v.is_empty() && self.entries.insert(v) {
                added += 1;
            }
        }
        added
    }

    pub fn remove(&mut self, values: Vec<String>) -> u32 {
        self.only_owner();
        let mut removed = 0;
        for v in values {
            if self.entries.remove(&norm(&v)) {
                removed += 1;
            }
        }
        removed
    }

    pub fn is_blocked(&self, value: String) -> bool {
        self.entries.contains(&norm(&value))
    }

    pub fn list(&self, from_index: Option<u32>, limit: Option<u32>) -> Vec<String> {
        let from = from_index.unwrap_or(0) as usize;
        let limit = limit.unwrap_or(100).min(500) as usize;
        self.entries.iter().skip(from).take(limit).cloned().collect()
    }

    pub fn owner(&self) -> AccountId {
        self.owner.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    fn ctx(who: &str) {
        testing_env!(VMContextBuilder::new().predecessor_account_id(who.parse().unwrap()).build());
    }

    #[test]
    fn owner_can_add_and_remove() {
        ctx("owner.testnet");
        let mut c = Blocklist::new("owner.testnet".parse().unwrap());
        assert_eq!(c.add(vec!["Evil.xyz ".into(), "drainer.testnet".into(), "evil.xyz".into()]), 2);
        assert!(c.is_blocked("EVIL.xyz".into()));
        assert_eq!(c.list(None, None).len(), 2);
        assert_eq!(c.remove(vec!["evil.xyz".into()]), 1);
        assert!(!c.is_blocked("evil.xyz".into()));
    }

    #[test]
    #[should_panic(expected = "only the owner")]
    fn stranger_cannot_add() {
        ctx("owner.testnet");
        let mut c = Blocklist::new("owner.testnet".parse().unwrap());
        ctx("stranger.testnet");
        c.add(vec!["x.com".into()]);
    }
}
