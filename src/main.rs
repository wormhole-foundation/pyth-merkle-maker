use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use anchor_lang::prelude::AnchorSerialize;
use anyhow::Error;
use pythnet_sdk::accumulators::merkle::MerkleTree;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
mod fast_merkle;
mod pyth_types;
use pyth_types::*;
mod chain_ids;
use chain_ids::*;

use crate::fast_merkle::MerkleTree as FastMerkleTree;

#[derive(Debug, Deserialize, Clone)]
struct CsvRow {
    chain_id: u16,
    address: String,
    amount: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Claim {
    index: usize,
    address: String,
    chain: String,
    chain_id: u16,
    amount: u64,
    #[serde(serialize_with = "serialize_hex", deserialize_with = "deserialize_hex")]
    preimage: Vec<u8>,
    #[serde(serialize_with = "serialize_hex", deserialize_with = "deserialize_hex")]
    hashes: Vec<u8>
}

// Serializer
// Custom serialization function for hexadecimal strings
fn serialize_hex<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(bytes))
}

// Custom deserialization function for hexadecimal strings
fn deserialize_hex<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_string = String::deserialize(deserializer)?;
    hex::decode(&hex_string).map_err(serde::de::Error::custom)
}


fn main() {
    // Path to the CSV file
    let csv_file_path = "data.csv";

    // Read the CSV file and parse its contents
    if let Err(e) = read_csv(csv_file_path) {
        eprintln!("Error reading CSV file: {}", e);
    }
}

fn read_csv(file_path: &str) -> Result<(), Error> {
    // Read the contents of the CSV file
    let csv_content = std::fs::read_to_string(file_path)?;

    // Parse CSV content into CSV rows
    let mut csv_reader = csv::Reader::from_reader(csv_content.as_bytes());
    let mut parsed_data: Vec<Claim> = Vec::new();
    let mut merkle_tree = FastMerkleTree::new();
    let mut i=0usize;
    for result in csv_reader.deserialize() {
        let record: CsvRow = result?;
        
        let claim = ClaimInfo::try_from(record.clone())?;
        let chain = ChainId::try_from(record.chain_id)?;
        let mut address = record.address;
        if chain == ChainId::Ethereum {
            let mut normalized_address = format!("0000000000000000000000000000000000000000{}", address.trim_start_matches("0x").to_ascii_lowercase());
            normalized_address = format!("0x{}", normalized_address[normalized_address.len()-40..].to_string());
            if normalized_address.ne(&address) {
                println!("WARNING: EVM address failed normalization: \"{}\"", &address);
                address = normalized_address   
            }
        } else if chain == ChainId::Aptos {
            let mut normalized_address = format!("0000000000000000000000000000000000000000000000000000000000000000{}", address.trim_start_matches("0x").to_ascii_lowercase());
            normalized_address = format!("0x{}", normalized_address[normalized_address.len()-64..].to_string());
            if normalized_address.ne(&address) {
                println!("WARNING: Aptos address failed normalization: \"{}\"", &address);
                address = normalized_address   
            }
        } else if chain == ChainId::Sui {
            let mut normalized_address = format!("0000000000000000000000000000000000000000000000000000000000000000{}", address.trim_start_matches("0x").to_ascii_lowercase());
            normalized_address = format!("0x{}", normalized_address[normalized_address.len()-64..].to_string());
            if normalized_address.ne(&address) {
                println!("WARNING: Sui address failed normalization: \"{}\"", &address);
                address = normalized_address   
            }
        }
        parsed_data.push(Claim {
            index: i,
            address,
            chain: chain.to_string(),
            chain_id: record.chain_id,
            amount: record.amount,
            preimage: claim.try_to_vec()?,
            hashes: vec![]
        });
        i+=1;
        merkle_tree.add_leaf(&claim.try_to_vec()?)
    }

    for n in 0..i.next_power_of_two() - i {
        merkle_tree.add_hash_unchecked(FastMerkleTree::hash_null())
    }
    
    println!("Merklizing {} items", i);
    merkle_tree.merklize()?;

    // let merkle_tree: MerkleTree<SolanaHasher> = MerkleTree::new(
    //     parsed_data
    //         .iter()
    //         .map(|item| item.preimage.as_slice())
    //         .collect::<Vec<&[u8]>>()
    //         .as_slice(),
    // )
    // .unwrap();

    let root = hex::encode(&merkle_tree.get_merkle_root()?);

    println!("Merklized {} items", i);

    // Create a folder to store files
    create_folder(&format!("output/{}", &root))?;

    // Process parsed data
    // let proof_a = hex::encode(&merkle_tree.find_path(1).to_bytes());
    // let proof_b = hex::encode(&merkle_tree.prove(&parsed_data[0].preimage).unwrap().to_bytes());

    // println!("A: {}\nB:{}", proof_a, proof_b);
    // let proof_a = hex::encode(&merkle_tree.find_path(0).to_bytes());
    // let proof_b = hex::encode(&merkle_tree.prove(&parsed_data[1].preimage).unwrap().to_bytes());

    // println!("A: {}\nB:{}", proof_a, proof_b);

    // let proof_a = hex::encode(&merkle_tree.find_path(1).to_bytes());
    // let proof_b = hex::encode(&merkle_tree.prove(&parsed_data[2].preimage).unwrap().to_bytes());

    // println!("A: {}\nB:{}", proof_a, proof_b);

    // let proof_a = hex::encode(&merkle_tree.find_path(2).to_bytes());
    // let proof_b = hex::encode(&merkle_tree.prove(&parsed_data[3].preimage).unwrap().to_bytes());

    // println!("A: {}\nB:{}", proof_a, proof_b);

    // panic!();
    parsed_data.par_iter().for_each(|c| {
        let mut final_claim = c.clone();
        final_claim.hashes = merkle_tree.merkle_proof_index(final_claim.index).unwrap().get_pairing_hashes();
        let mut file = File::create(format!("output/{}/{}_{}.json", root, final_claim.address.clone(), final_claim.chain_id.clone())).expect("Failed to open file");
        let json = serde_json::to_string(&final_claim).expect("Failed to convert to JSON");
        file.write_all(json.as_bytes()).expect("Failed to write to file");
    });
    println!("Successfully merklized {}!", &root);

    Ok(())
}

fn create_folder(folder_path: &str) -> Result<(), Error> {
    // Create the folder if it doesn't exist
    if !Path::new(folder_path).exists() {
        fs::create_dir(folder_path)?;
        println!("Folder '{}' created successfully.", folder_path);
    } else {
        println!("Folder '{}' already exists.", folder_path);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::fast_merkle::MerkleTree as FastMerkleTree;

    use super::*;
    use core::panic;
    use std::{self, fs::{self, File}, io::Read, str::FromStr};
    use anyhow::{ Result, Error };
    use pythnet_sdk::accumulators::{merkle::{self, MerklePath, MerkleRoot}, Accumulator};
    use rand::prelude::SliceRandom;
    use rand::thread_rng;
    use rayon::iter::IntoParallelIterator;
    use solana_program::pubkey;

    #[test]
    fn validate_random() {
        // Swap this out for any set of proofs you would like to validate
        let root = "e853ab0fa5b4579a08339c75e3e2cc88ffdecd0c";
        let root_bytes = hex::decode(root).unwrap();
        let mut root_array: [u8;20] = [0u8;20];
        root_array.clone_from_slice(&root_bytes);

        let filename = pick_random_file(&format!("output/{}/", &root)).expect("Failed to select random file");
        // Get the file:
        let mut file = File::open(&format!("output/{}/{}", &root,&filename)).expect("Failed to open file");
        let mut json_string = String::new();
        file.read_to_string(&mut json_string).expect("Failed to read JSON file");

        println!("{}", json_string);

        // Deserialize the JSON string into a struct
        let claim: Claim = serde_json::from_str(&json_string).expect("Failed to deserialize JSON file");

        let root = MerkleRoot::<SolanaHasher>::new(root_array);

        if !root.check(MerklePath::<SolanaHasher>::new(claim.hashes.chunks_exact(20).map(|chunk| {
            let mut array = [0u8; 20];
            array.copy_from_slice(chunk);
            array
        })
        .collect()), &claim.preimage) {
            panic!("Invalid merkle proof")
        }
    }

    #[test]
    fn validate_random_1000() {
        (0..1000).into_par_iter().for_each(|_| {
            validate_random()
        });
    }

    #[test]
    fn make_test_merkle_tree() {

        let mut evm_pubkey: [u8; 20] = [0u8; 20];
        evm_pubkey.copy_from_slice(&hex::decode("f3f9225A2166861e745742509CED164183a626d7").unwrap());

        let mut aptos_address: [u8; 32] = [0u8; 32];
        aptos_address.copy_from_slice(
            &hex::decode("7e7544df4fc42107d4a60834685dfd9c1e6ff048f49fe477bc19c1551299d5cb").unwrap(),
        );

        let mut sui_address: [u8; 32] = [0u8; 32];
        sui_address.copy_from_slice(
            &hex::decode("87a7ec050788fbaa9cd842b4cf9915949931af94806404bba661f1ac3d338148").unwrap(),
        );

        let mut algorand_address: [u8;36] = [0u8; 36];
        algorand_address.copy_from_slice(&base32::decode(base32::Alphabet::RFC4648 { padding: false }, "JS22X5VNPH57LK54ZL6ME2OYLTJGKHWUXCC3LBU7EQNO34FFXIUYKBWSCU").unwrap());

        let merkle_items: Vec<ClaimInfo> = vec![
            ClaimInfo {
                amount:   4000,
                identity: Identity::Cosmwasm {
                    address: "cosmos1lv3rrn5trdea7vs43z5m4y34d5r3zxp484wcpu".into(),
                },
            },
            ClaimInfo {
                amount:   4000,
                identity: Identity::Injective { 
                    address: "inj176tzzf37xpkxx8fauc67a6w902wz8jtv5sq32z".into()
                },
            },
            ClaimInfo {
                amount:   1000,
                identity: Identity::Discord {
                    username: "pepito".to_string(),
                },
            },
            ClaimInfo {
                amount:   1000,
                identity: Identity::Solana {
                    pubkey: pubkey!("3kzAHeiucNConBwKQVHyLcG3soaMzSZkvs4y14fmMgKL").into(),
                },
            },
            ClaimInfo {
                amount:   2000,
                identity: Identity::Evm {
                    pubkey: evm_pubkey.into(),
                },
            },
            ClaimInfo {
                amount:   3000,
                identity: Identity::Aptos {
                    address: aptos_address.into(),
                },
            },
            ClaimInfo {
                amount:   5000,
                identity: Identity::Sui {
                    address: sui_address.into(),
                },
            },
            ClaimInfo {
                amount:   2000,
                identity: Identity::Algorand {
                    address: algorand_address.into(),
                },
            },
        ];

        let merkle_items_serialized = merkle_items
            .iter()
            .map(|item| item.try_to_vec().unwrap())
            .collect::<Vec<Vec<u8>>>();

        merkle_items_serialized.iter().for_each(|i| println!("{}", hex::encode(i)));

        let merkle_tree: MerkleTree<SolanaHasher> = MerkleTree::new(
            merkle_items_serialized
                .iter()
                .map(|item| item.as_slice())
                .collect::<Vec<&[u8]>>()
                .as_slice(),
        )
        .unwrap();

        println!(
            "Merkle root from Rust, check this against the JS test merkleTree.test.ts: {:?}",
            hex::encode(merkle_tree.root.as_bytes())
        );

        println!("Proofs in order");
        for claim_info in merkle_items {
            println!(
                "{:?}",
                hex::encode(
                    merkle_tree
                        .prove(&claim_info.try_to_vec().unwrap())
                        .unwrap()
                        .to_bytes()
                )
            );
        }
    }

    #[test]
    fn make_fast_merkle_tree() {

        // 0cb6d3048024d99d68a164ec21a5266c64ed749edb27bc96102425779015849057189057668bbf117ca887921ca26514b68eb3bc10b8a800f52851fa

        let mut evm_pubkey: [u8; 20] = [0u8; 20];
        evm_pubkey.copy_from_slice(&hex::decode("f3f9225A2166861e745742509CED164183a626d7").unwrap());

        let mut aptos_address: [u8; 32] = [0u8; 32];
        aptos_address.copy_from_slice(
            &hex::decode("7e7544df4fc42107d4a60834685dfd9c1e6ff048f49fe477bc19c1551299d5cb").unwrap(),
        );

        let mut sui_address: [u8; 32] = [0u8; 32];
        sui_address.copy_from_slice(
            &hex::decode("87a7ec050788fbaa9cd842b4cf9915949931af94806404bba661f1ac3d338148").unwrap(),
        );

        let mut algorand_address: [u8;36] = [0u8; 36];
        algorand_address.copy_from_slice(&base32::decode(base32::Alphabet::RFC4648 { padding: false }, "JS22X5VNPH57LK54ZL6ME2OYLTJGKHWUXCC3LBU7EQNO34FFXIUYKBWSCU").unwrap());

        let merkle_items: Vec<ClaimInfo> = vec![
            ClaimInfo {
                amount:   4000,
                identity: Identity::Cosmwasm {
                    address: "cosmos1lv3rrn5trdea7vs43z5m4y34d5r3zxp484wcpu".into(),
                },
            },
            ClaimInfo {
                amount:   4000,
                identity: Identity::Injective { 
                    address: "inj176tzzf37xpkxx8fauc67a6w902wz8jtv5sq32z".into()
                },
            },
            ClaimInfo {
                amount:   1000,
                identity: Identity::Discord {
                    username: "pepito".to_string(),
                },
            },
            ClaimInfo {
                amount:   1000,
                identity: Identity::Solana {
                    pubkey: pubkey!("3kzAHeiucNConBwKQVHyLcG3soaMzSZkvs4y14fmMgKL").into(),
                },
            },
            ClaimInfo {
                amount:   2000,
                identity: Identity::Evm {
                    pubkey: evm_pubkey.into(),
                },
            },
            ClaimInfo {
                amount:   3000,
                identity: Identity::Aptos {
                    address: aptos_address.into(),
                },
            },
            ClaimInfo {
                amount:   5000,
                identity: Identity::Sui {
                    address: sui_address.into(),
                },
            },
            ClaimInfo {
                amount:   2000,
                identity: Identity::Algorand {
                    address: algorand_address.into(),
                },
            },
        ];

        let mut merkle_tree = FastMerkleTree::new();

        merkle_items
            .iter()
            .for_each(|item| merkle_tree.add_leaf(&item.try_to_vec().unwrap()));

        merkle_tree.merklize().unwrap();

        println!(
            "Merkle root from Rust, check this against the JS test merkleTree.test.ts: {:?}",
            hex::encode(merkle_tree.get_merkle_root().unwrap())
        );

        for i in 0..merkle_items.len() {
            let proof = merkle_tree.merkle_proof_index(i).unwrap();
            println!("{}", hex::encode(proof.get_pairing_hashes()));    
        }

        // 56b88da9a90ff950b2f4376081d28fe5c5321437

        // 56b88da9a90ff950b2f4376081d28fe5c5321437

        // println!("Proofs in order");
        // for claim_info in merkle_items {
        //     println!(
        //         "{:?}",
        //         hex::encode(
        //             merkle_tree
        //                 .get_leaf_hash(&claim_info.try_to_vec().unwrap())
        //                 .unwrap()
        //                 .to_bytes()
        //         )
        //     );
        // }
    }


    fn pick_random_file(dir_path: &str) -> Result<String, Error> {
        // Read the contents of the directory
        let entries = fs::read_dir(dir_path)?;
    
        // Collect file paths into a vector
        let mut files: Vec<_> = entries.filter_map(|entry| {
            if let Ok(entry) = entry {
                if let Some(file_name) = entry.file_name().to_str() {
                    Some(file_name.to_string())
                } else {
                    None
                }
            } else {
                None
            }
        }).collect();
    
        // Shuffle the vector randomly
        let mut rng = thread_rng();
        files.shuffle(&mut rng);
    
        // Pick a random file
        if let Some(random_file) = files.first() {
            println!("Randomly picked file: {}", random_file);
            Ok(random_file.clone())
        } else {
            Err(Error::msg("Failed to find random file"))
        }
    }
}