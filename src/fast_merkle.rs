// [Redacted] merkle tree sucks. Let's 200x its performance.
// use anchor_lang::prelude::*;
use rayon::{prelude::*, iter::{IntoParallelIterator,ParallelIterator}};
use solana_program::keccak;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MerkleError {
    #[error("Leaf out of range")]
    LeafOutOfRange,
    #[error("Branch out of range")]
    BranchOutOfRange,
    #[error("Leaf not found")]
    LeafNotFound,
    #[error("Merkle tree not merklized")]
    TreeNotMerklized,
    #[error("Merkle tree is empty")]
    TreeEmpty,
    #[error("Invalid hash size")]
    InvalidHashSize,
}

#[derive(Debug, Clone)]
pub struct MerkleProof {
    index: u32,
    hashes: Vec<u8>
}

impl MerkleProof {
    pub fn new(index: u32, hashes: Vec<u8>) -> Self {
        Self {
            index,
            hashes
        }
    }

    // Hash with defined hashing algorithm and truncate to defined length
    pub fn hash(&self, m: &[u8]) -> [u8;MerkleTree::HASH_LENGTH] {
        let mut b = [0u8;MerkleTree::HASH_LENGTH];
        b.clone_from_slice(&keccak::hash(m).0[..20]);
        b
    }

    // Merklize from a leaf
    pub fn merklize(&self, leaf: &[u8]) -> [u8;MerkleTree::HASH_LENGTH] {
        // If our pairing hashes are empty, return the untruncated hash
        match self.hashes.len() == 0 {
            true => MerkleTree::hash_leaf(leaf),
            false => self.merklize_hash_unchecked(MerkleTree::hash_leaf(leaf))
        }
    }

    // Merklize from a leaf
    // pub fn merklize_hash(&self, hash: &[u8]) -> Result<Vec<u8>> {
    //     // If pairing hashes are empty and our hash is 32 bytes long, return early
    //     if hash.len() != self.hash_size as usize {
    //         match self.hashes.is_empty() && hash.len() == 32 {
    //             true => return Ok(hash.to_vec()),
    //             false => return Err(MerkleError::InvalidHashSize.into())
    //         }
    //     }
    //     self.merklize_hash_unchecked(hash)
    // }
    fn merklize_hash_unchecked(&self, hash: [u8;MerkleTree::HASH_LENGTH]) -> [u8;MerkleTree::HASH_LENGTH] {
        let mut current = hash;
        let hashes: Vec<[u8;20]> = self.hashes.chunks_exact(20).map(|h| {
            let mut b = [0u8;20];
            b.clone_from_slice(h);
            b
        }).collect();

        for h in hashes {
            current = MerkleTree::hash_node(&current, &h);
        }

        current
    }

    pub fn get_pairing_hashes(&self) -> Vec<u8> {
        self.hashes.clone()
    }
}

const LEAF_PREFIX: &[u8] = &[0];
const NODE_PREFIX: &[u8] = &[1];
const NULL_PREFIX: &[u8] = &[2];

#[derive(Debug, Clone)]
pub struct MerkleTree {
    root: [u8; Self::HASH_LENGTH],
    hashes: Vec<Vec<[u8; Self::HASH_LENGTH]>>
}

// For non-Solana targets, use Rayon to hash/merklize in parallel
impl MerkleTree {
    pub const HASH_LENGTH: usize = 20;

    fn merklize_unchecked(h: &Vec<[u8; Self::HASH_LENGTH]>) -> Vec<[u8;Self::HASH_LENGTH]> {
        h.par_chunks(2).into_par_iter().map(|h| {
            if h.len() > 1 {
                Self::hash_node(&h[0],&h[1])
            } else {
                Self::hash_node(&h[0], &Self::hash_null())
            }
        }).collect()
    }
    // Initialize a new tree with configurable size and hashing params
    pub fn new() -> Self {
        Self {
            root: [0u8;Self::HASH_LENGTH],
            hashes: vec![vec![]]
        }
    }

    // Hash with defined hashing algorithm and truncate to defined length
    fn hash_leaf(m: &[u8]) -> [u8; Self::HASH_LENGTH] {
        let mut h = [0u8;Self::HASH_LENGTH];
        let hash = keccak::hashv(&vec![
            LEAF_PREFIX,
            m
        ]).0;
        h.clone_from_slice(&hash[..20]);
        h
    }

    fn hash_node(l: &[u8;Self::HASH_LENGTH],r: &[u8;Self::HASH_LENGTH]) -> [u8; Self::HASH_LENGTH] {
        let mut h = [0u8;Self::HASH_LENGTH];
        let hash = keccak::hashv(&vec![
            NODE_PREFIX,
            (if l <= r { l } else { r }).as_ref(),
            (if l <= r { r } else { l }).as_ref()
        ]).0;
        h.clone_from_slice(&hash[..20]);
        h
    }

    pub fn hash_null() -> [u8; Self::HASH_LENGTH] {
        let mut h = [0u8;Self::HASH_LENGTH];
        let hash = keccak::hashv(&vec![
            NULL_PREFIX
        ]).0;
        h.clone_from_slice(&hash[..20]);
        h
    }

    // Hash and append a leaf
    pub fn add_leaf(&mut self, leaf: &[u8]) {
        // Double hash to prevent length extension attacks
        // No need for length check
        self.add_hash_unchecked(Self::hash_leaf(leaf))
    }

    // Append a hash without a length check. Use with normalized data
    pub fn add_hash_unchecked(&mut self, hash: [u8; Self::HASH_LENGTH]) {
        self.hashes[0].push(hash);
    }

    pub fn merklize(&mut self) -> Result<(), MerkleError> {
        let len = self.hashes[0].len();
        match len {
            0 => Err(MerkleError::TreeEmpty.into()),
            1 => {
                self.reset();
                self.root = self.hashes[0][0].clone();
                Ok(())
            }, 
            _ => {
                self.reset();
                let mut count = self.hashes[0].len();
                while count > 2 {
                    let h: Vec<[u8;Self::HASH_LENGTH]> = Self::merklize_unchecked(self.hashes.last().ok_or(MerkleError::BranchOutOfRange)?);
                    count = h.len();
                    self.hashes.push(h);
                }
                self.root = Self::merklize_unchecked(self.hashes.last().ok_or(MerkleError::BranchOutOfRange)?)[0].clone();
                Ok(())
            }
        }
    }

    pub fn reset(&mut self) {
        self.hashes.truncate(1);
    }

    fn merklized(&self) -> Result<(), MerkleError> {
        if self.root.eq(&[0u8;Self::HASH_LENGTH]) {
            return Err(MerkleError::TreeNotMerklized.into())
        }
        Ok(())
    }

    fn within_range(&self, index: usize) -> Result<(), MerkleError> {
        let len = self.hashes[0].len();
        if index > len {
            return Err(MerkleError::LeafOutOfRange.into())
        }
        Ok(())
    }

    fn get_hash_index(&self, hash: [u8;20]) -> Result<usize, MerkleError> {
        match self.hashes[0].binary_search(&hash) {
            Ok(i) => Ok(i),
            Err(_) => Err(MerkleError::LeafNotFound.into())
        }
    }

    pub fn get_merkle_root(&self) -> Result<[u8;Self::HASH_LENGTH], MerkleError> {
        self.merklized()?;
        Ok(self.root.clone())
    }

    pub fn get_leaf_hash(&self, i: usize) -> Result<[u8;Self::HASH_LENGTH], MerkleError> {
        self.within_range(i)?;
        Ok(self.hashes[0][i].clone())
    }

    pub fn merkle_proof_hash(&self, hash: [u8;Self::HASH_LENGTH]) -> Result<MerkleProof, MerkleError> {
        self.merklized()?;
        let i = self.get_hash_index(hash)?;
        self.merkle_proof_index_unchecked(i)
    }

    pub fn merkle_proof_index(&self, i: usize) -> Result<MerkleProof, MerkleError> {
        self.merklized()?;
        self.within_range(i)?;
        self.merkle_proof_index_unchecked(i)
    }

    fn merkle_proof_index_unchecked(&self, i: usize) -> Result<MerkleProof, MerkleError> {
        let len = self.hashes[0].len();
        match len {
            // We can't have zero leaves in a Merkle tree
            0 => Err(MerkleError::TreeEmpty.into()),
            // If we only have one leaf, the 0th hash is the root
            1 => Ok(MerkleProof::new(
                i as u32,
                vec![],
            )),
            _ => {
                let mut hashes: Vec<Vec<u8>> = vec![];
                let mut n = i;
                // 0, 1, 2, 3
                for x in 0..self.hashes.len() {
                    n = match n%2 == 0 {
                        true => usize::min(n+1, self.hashes[x].len()),
                        false => n-1
                    };
                    
                    match self.hashes[x].get(n) {
                        Some(h) => {
                            hashes.push(h.clone().to_vec())
                        },
                        None => hashes.push(self.hashes[x][n-1].clone().to_vec())
                    }
                    n = n.saturating_div(2);
                }
                Ok(MerkleProof::new(
                    i as u32,
                    hashes.concat()
                ))
            }
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use hex_literal::hex;
//     use crate::{merkle, HashingAlgorithm, MerkleProof};

//     use super::MerkleTree;

//     #[test]
//     fn merkle_tree_block_9_test() {
//         let mut merkle_tree = MerkleTree::new(
//             crate::HashingAlgorithm::Sha256d,
//             32
//         );
//         merkle_tree.add_hash(hex!("c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704").to_vec()).unwrap();
//         merkle_tree.merklize().unwrap();
//         assert_eq!(hex!("c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704").to_vec(), merkle_tree.root);
//         for n in 0..merkle_tree.hashes[0].len() {
//             let proof = merkle_tree.merkle_proof_index(n).unwrap();
//             assert_eq!(merkle_tree.root, proof.merklize_hash(&merkle_tree.get_leaf_hash(n).unwrap()).unwrap());
//         }
//     }

//     #[test]
//     fn merkle_tree_bitcoin_block_100000_test() {
//         let mut merkle_tree = MerkleTree::new(
//             crate::HashingAlgorithm::Sha256d,
//             32
//         );

//         merkle_tree.add_hashes(vec![
//             hex!("876dd0a3ef4a2816ffd1c12ab649825a958b0ff3bb3d6f3e1250f13ddbf0148c").to_vec(),
//             hex!("c40297f730dd7b5a99567eb8d27b78758f607507c52292d02d4031895b52f2ff").to_vec(),
//             hex!("c46e239ab7d28e2c019b6d66ad8fae98a56ef1f21aeecb94d1b1718186f05963").to_vec(),
//             hex!("1d0cb83721529a062d9675b98d6e5c587e4a770fc84ed00abc5a5de04568a6e9").to_vec()
//         ]).unwrap();

//         merkle_tree.merklize().unwrap();
//         assert_eq!(hex!("6657a9252aacd5c0b2940996ecff952228c3067cc38d4885efb5a4ac4247e9f3").to_vec(), merkle_tree.root);
//         for n in 0..merkle_tree.hashes[0].len() {
//             let proof = merkle_tree.merkle_proof_index(n).unwrap();
//             assert_eq!(merkle_tree.root, proof.merklize_hash(&merkle_tree.get_leaf_hash(n).unwrap()).unwrap());
//         }
//     }

//     #[test]
//     fn merkle_tree_bitcoin_block_100002_test() {
//         let mut merkle_tree = MerkleTree::new(
//             crate::HashingAlgorithm::Sha256d,
//             32
//         );

//         merkle_tree.add_hashes(vec![
//             hex!("a3f3ac605d5e4727f4ea72e9346a5d586f0231460fd52ad9895bc8240d871def").to_vec(),
//             hex!("076d0317ee70ee36cf396a9871ab3bf6f8e6d538d7f8a9062437dcb71c75fcf9").to_vec(),
//             hex!("2ee1e12587e497ada70d9bd10d31e83f0a924825b96cb8d04e8936d793fb60db").to_vec(),
//             hex!("7ad8b910d0c7ba2369bc7f18bb53d80e1869ba2c32274996cebe1ae264bc0e22").to_vec(),
//             hex!("4e3f8ef2e91349a9059cb4f01e54ab2597c1387161d3da89919f7ea6acdbb371").to_vec(),
//             hex!("e0c28dbf9f266a8997e1a02ef44af3a1ee48202253d86161d71282d01e5e30fe").to_vec(),
//             hex!("8719e60a59869e70a7a7a5d4ff6ceb979cd5abe60721d4402aaf365719ebd221").to_vec(),
//             hex!("5310aedf9c8068f1e862ac9186724f7fdedb0aa9819833af4f4016fca6d21fdd").to_vec(),
//             hex!("201f4587ec86b58297edc2dd32d6fcd998aa794308aac802a8af3be0e081d674").to_vec()
//         ]).unwrap();

//         merkle_tree.merklize().unwrap();

//         assert_eq!(hex!("5275289558f51c9966699404ae2294730c3c9f9bda53523ce50e9b95e558da2f").to_vec(), merkle_tree.root);

//         for n in 0..merkle_tree.hashes[0].len() {
//             let proof = merkle_tree.merkle_proof_index(n).unwrap();          
//             assert_eq!(merkle_tree.root, proof.merklize_hash(&merkle_tree.hashes[0][n]).unwrap());
//         }
//     }

//     #[test]
//     fn merkle_tree_payout_test() {
//         let mut merkle_tree = MerkleTree::new(
//             crate::HashingAlgorithm::Sha256,
//             16
//         );

//         struct Account {
//             chain: u16,
//             address: Vec<u8>,
//             amount: u64,
//         }

//         impl Account {
//             pub fn to_bytes(&self) -> Vec<u8> {
//                 let mut m = self.chain.to_le_bytes().to_vec();
//                 m.extend_from_slice(&[self.address.len() as u8]);
//                 m.extend_from_slice(&self.address);
//                 m.extend_from_slice(&self.amount.to_le_bytes());
//                 m
//             }
//         }

//         let leaf_1 = Account { chain: 1, address: hex!("c0ffee254729296a45a3885639AC7E10F9d54979").to_vec(), amount: 1337 }.to_bytes();
//         let leaf_2 = Account { chain: 1, address: hex!("999999cf1046e68e36E1aA2E0E07105eDDD1f08E").to_vec(), amount: 1337 }.to_bytes();

//         merkle_tree.add_leaf(&leaf_1);
//         merkle_tree.add_leaf(&leaf_2);

//         merkle_tree.merklize().unwrap();

//         assert_eq!(hex!("59f9111666f968b79593c142694cb662").to_vec(), merkle_tree.hashes[0][0]);
//         assert_eq!(hex!("61ebf6f4d1af532451e53c2d2a303390").to_vec(), merkle_tree.hashes[0][1]);
//         assert_eq!(hex!("ed89c53c2635102579a7a002249f7c97460d31ef72baaafd6960be39546c6002").to_vec(), merkle_tree.root);

//         let proof = merkle_tree.merkle_proof_index(0).unwrap();
//         assert_eq!(merkle_tree.root, proof.merklize(&leaf_1).unwrap());
//         let proof2 = merkle_tree.merkle_proof_index(1).unwrap();
//         assert_eq!(merkle_tree.root, proof2.merklize(&leaf_2).unwrap());
//     }

//     #[test]
//     fn test_airdrop() {
//         let mut merkle_tree = MerkleTree::new(crate::HashingAlgorithm::Sha256, 20);
//         merkle_tree.add_leaves(
//             &vec![
//                 hex!("00000000010039050000000000004cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29").to_vec(), // Sol
//                 hex!("01000000020039050000000000007e5f4552091a69125d5dfcb7b8c2659029395bdf").to_vec(), // Eth
//                 hex!("0200000021003905000000000000d0c2c91eda34bbfbaec6cfb9c7bb913e57dab3cbec4018a4b3f5e55531cd63af").to_vec(), // Sui
//                 hex!("03000000220039050000000000004cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29").to_vec() // Aptos
//             ]
//         ).unwrap();
//         merkle_tree.merklize().unwrap();

//         let proof = MerkleProof::new(HashingAlgorithm::Sha256, 20, 0, merkle_tree.merkle_proof_index(0).unwrap().get_pairing_hashes());
//         let proof_root = proof.merklize(&hex!("00000000010039050000000000004cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29")).unwrap();
//         // sol_log(&format!("{:?}", self.to_leaf_preimage()));
//         // sol_log(&format!("{:?}", proof_root));
//         // require!(root.eq(&proof_root), AirdropError::InvalidMerkleProof);
//         // Ok(())
//         println!("{:?}", hex::encode(merkle_tree.get_merkle_root().unwrap()));
//         println!("{:?}", hex::encode(proof_root))
        
//     }
// }