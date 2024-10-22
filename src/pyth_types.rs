use core::panic;
use std::{any, io::Read};
use crate::{ChainId, Claim, CsvRow};
use anchor_lang::prelude::{borsh::de, *};
use bech32::ToBase32;
use blake2_rfc::blake2b::Blake2b;
use pythnet_sdk::hashers::Hasher;
use sha3::Digest;
use solana_program::keccak::hashv;
////////////////////////////////////////////////////////////////////////////////
// Instruction calldata.
////////////////////////////////////////////////////////////////////////////////

#[derive(AnchorDeserialize, AnchorSerialize, Clone)]
pub struct ClaimInfo {
    pub identity: Identity,
    pub amount:   u64,
}

/**
 * This is the identity that the claimant will use to claim tokens.
 * A claimant can claim tokens for 1 identity on each ecosystem.
 * Typically for a blockchain it is a public key in the blockchain's address space.
 */
#[derive(AnchorDeserialize, AnchorSerialize, Clone)]
pub enum Identity {
    Discord { username: String },
    Solana { pubkey: Ed25519Pubkey },
    Evm { pubkey: EvmPubkey },
    Sui { address: SuiAddress },
    Aptos { address: AptosAddress },
    Cosmwasm { address: CosmosBech32Address },
    Injective { address: CosmosBech32Address },
    Algorand { address: AlgorandAddress }
}

impl TryFrom<CsvRow> for ClaimInfo {
    type Error = anyhow::Error;

    fn try_from(value: CsvRow) -> std::prelude::v1::Result<Self, Self::Error> {
        let chain_id = ChainId::try_from(value.chain_id).expect("Invalid chain id");
        
        let claim = match chain_id {
            ChainId::Discord => {
                ClaimInfo {
                    identity: Identity::Discord { username: value.address },
                    amount: value.amount
                }
            },
            ChainId::Solana => {
                ClaimInfo {
                    identity: Identity::Solana { pubkey: value.address.try_into()? },
                    amount: value.amount
                }
            },
            ChainId::Ethereum => {
                ClaimInfo {
                    identity: Identity::Evm { pubkey:value.address.try_into()? },
                    amount: value.amount
                }
            },
            ChainId::Sui => {
                ClaimInfo {
                    identity: Identity::Sui { address: value.address.try_into()? },
                    amount: value.amount
                }
            },
            ChainId::Aptos => {
                ClaimInfo {
                    identity: Identity::Aptos { address: value.address.try_into()? },
                    amount: value.amount
                }
            },
            ChainId::Terra | ChainId::Osmosis => {
                let (_hrp, _address_string, _variant) = bech32::decode(&value.address).expect(&format!("Invalid {} Bech32 addess {}", chain_id.to_string(), value.address));
                ClaimInfo {
                    identity: Identity::Cosmwasm { address: CosmosBech32Address(value.address) },
                    amount: value.amount
                }
            },
            ChainId::Injective | ChainId::Evmos => {
                let (_hrp, _address_string, _variant) = bech32::decode(&value.address).expect(&format!("Invalid Injective Bech32 addess {}", value.address));
                ClaimInfo {
                    identity: Identity::Injective { address: CosmosBech32Address(value.address) },
                    amount: value.amount
                }
            }, 
            ChainId::Algorand => {
                ClaimInfo {
                    identity: Identity::Algorand { address: value.address.try_into()? },
                    amount: value.amount
                }
            },
            _ => panic!("Unsupported Chain ID")
        };
        Ok(claim)
    }
}

/* Ed25519 */

#[derive(AnchorDeserialize, AnchorSerialize, Clone, PartialEq, Debug)]
pub struct Ed25519Pubkey([u8; Ed25519Pubkey::LEN]);
impl Ed25519Pubkey {
    pub const LEN: usize = 32;
}

impl TryFrom<String> for Ed25519Pubkey {

    type Error = anyhow::Error;
    
    fn try_from(value: String) -> std::prelude::v1::Result<Self, Self::Error> {
        let decoded = bs58::decode(value).into_vec()?;
        let mut bytes = [0u8; 32];
        bytes.clone_from_slice(&decoded);
        Ok(Self(bytes))
    }
}

impl From<Pubkey> for Ed25519Pubkey {
    fn from(pubkey: Pubkey) -> Self {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(pubkey.as_ref());
        Self(bytes)
    }
}

impl Ed25519Pubkey {
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        self.0
    }
}

/* EVM */

#[derive(AnchorDeserialize, AnchorSerialize, Clone, Copy, PartialEq, Debug)]
pub struct EvmPubkey([u8; Self::LEN]);

impl EvmPubkey {
    pub const LEN: usize = 20;

    pub fn as_bytes(&self) -> [u8; Self::LEN] {
        self.0
    }
}


impl TryFrom<String> for EvmPubkey {
    type Error = anyhow::Error;

    fn try_from(value: String) -> std::prelude::v1::Result<Self, Self::Error> {
        let unpadded_value = value.replace("0x", "");
        let lowercase_value = unpadded_value.to_lowercase();
        let padded_value = format!("{:0>20}", lowercase_value);
        let decoded = hex::decode(padded_value)?;
        let mut bytes = [0u8;20];
        bytes.clone_from_slice(&decoded);
        Ok(Self(bytes))
    }
}

#[cfg(test)]
impl From<[u8; Self::LEN]> for EvmPubkey {
    fn from(bytes: [u8; Self::LEN]) -> Self {
        EvmPubkey(bytes)
    }
}

/* Cosmos  */

#[derive(AnchorDeserialize, AnchorSerialize, Clone, Debug)]
pub struct CosmosBech32Address(String);

impl From<EvmPubkey> for CosmosBech32Address {
    fn from(value: EvmPubkey) -> Self {
        CosmosBech32Address(
            bech32::encode(
                "inj",
                value.as_bytes().to_base32(),
                bech32::Variant::Bech32,
            )
            .unwrap(),
        )
    }
}


#[cfg(test)]
impl From<&str> for CosmosBech32Address {
    fn from(bytes: &str) -> Self {
        CosmosBech32Address(bytes.to_string())
    }
}

/* Algorand */

#[derive(Clone)]
pub struct AlgorandAddress([u8; Self::LEN]);

impl TryFrom<String> for AlgorandAddress {
    type Error = anyhow::Error;

    fn try_from(value: String) -> std::prelude::v1::Result<Self, Self::Error> {
        let decoded = base32::decode(base32::Alphabet::RFC4648 { padding: false }, &value).expect("Invalid Algorand address");
        let mut bytes = [0u8;36];
        bytes.clone_from_slice(&decoded);
        Ok(Self(bytes))
    }
}

impl AnchorSerialize for AlgorandAddress {
    fn serialize<W: std::io::prelude::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.0[..32])
    }
}

impl AnchorDeserialize for AlgorandAddress {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        let mut address = [0u8;36];
        buf.read_exact(&mut address)?;
        Ok(AlgorandAddress(address))
    }
    
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut address = [0u8;36];
        reader.read_exact(&mut address)?;
        Ok(AlgorandAddress(address))
    }
}

impl AlgorandAddress {
    pub const LEN: usize = 36;
}

/* 

If we need to know that an address came from a public key, Sha512/256 hashing is required. 
If we only need to know that a public key comes from an address, we can omit hashing and just take the first 32 bytes of the address because an Algorand address is just a 32 byte ed25519 pubkey with a 4 byte checksum at the end.

*/

impl From<Ed25519Pubkey> for AlgorandAddress {
    fn from(val: Ed25519Pubkey) -> Self {
        let mut hasher = sha2::Sha512_256::new();
        hasher.update(val.to_bytes());
        let checksum: [u8;32] = hasher.finalize().try_into().unwrap();
        let mut algorand_addr = [0u8; Self::LEN];
        algorand_addr[..32].clone_from_slice(&val.to_bytes());
        algorand_addr[32..].clone_from_slice(&checksum[28..]);
        AlgorandAddress(algorand_addr)
    }
}

impl From<[u8; Self::LEN]> for AlgorandAddress {
    fn from(bytes: [u8; Self::LEN]) -> Self {
        AlgorandAddress(bytes)
    }
}

/* Aptos */

pub const APTOS_SIGNATURE_SCHEME_ID: u8 = 0;

#[derive(AnchorDeserialize, AnchorSerialize, Clone)]
pub struct AptosAddress([u8; 32]);

impl AptosAddress {
    pub const LEN: usize = 32;
}

impl TryFrom<String> for AptosAddress {
    type Error = anyhow::Error;

    fn try_from(value: String) -> std::prelude::v1::Result<Self, Self::Error> {
        let trimmed_value = value.trim_start_matches("0x");
        let unpadded_value = format!("0000000000000000000000000000000000000000000000000000000000000000{}", trimmed_value);
        let padded_value = unpadded_value[unpadded_value.len()-64..].to_string();
        let decoded = hex::decode(padded_value)?;
        let mut bytes = [0u8;32];
        bytes.clone_from_slice(&decoded);
        Ok(Self(bytes))
    }
}

impl From<Ed25519Pubkey> for AptosAddress {
    fn from(val: Ed25519Pubkey) -> Self {
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(val.to_bytes());
        hasher.update([APTOS_SIGNATURE_SCHEME_ID]);
        let aptos_addr: [u8; 32] = hasher.finalize().try_into().unwrap();
        AptosAddress(aptos_addr)
    }
}

impl From<[u8; Self::LEN]> for AptosAddress {
    fn from(bytes: [u8; Self::LEN]) -> Self {
        AptosAddress(bytes)
    }
}

pub const SUI_SIGNATURE_SCHEME_ID: u8 = 0;

#[derive(AnchorDeserialize, AnchorSerialize, Clone)]
pub struct SuiAddress([u8; 32]);

impl SuiAddress {
    pub const LEN: usize = 32;
}

impl TryFrom<String> for SuiAddress {
    type Error = anyhow::Error;

    fn try_from(value: String) -> std::prelude::v1::Result<Self, Self::Error> {
        let unpadded_value = value.replace("0x", "");
        let padded_value = format!("{:0>20}", unpadded_value);
        let decoded = hex::decode(padded_value)?;
        let mut bytes = [0u8;32];
        bytes.clone_from_slice(&decoded);
        Ok(Self(bytes))
    }
}

impl From<Ed25519Pubkey> for SuiAddress {
    fn from(val: Ed25519Pubkey) -> Self {
        let mut context = Blake2b::new(32);
        let mut result = SuiAddress([0u8; 32]);
        context.update(&[SUI_SIGNATURE_SCHEME_ID]);
        context.update(&val.to_bytes());

        result.0.copy_from_slice(context.finalize().as_bytes());
        result
    }
}

impl From<[u8; Self::LEN]> for SuiAddress {
    fn from(bytes: [u8; Self::LEN]) -> Self {
        SuiAddress(bytes)
    }
}


/**
 * A hasher that uses the solana pre-compiled keccak256 function.
 */
#[derive(Default, Debug, Clone, PartialEq)]
pub struct SolanaHasher {}
impl Hasher for SolanaHasher {
    type Hash = [u8; 20];

    fn hashv(data: &[impl AsRef<[u8]>]) -> Self::Hash {
        let bytes = hashv(&data.iter().map(|x| x.as_ref()).collect::<Vec<&[u8]>>());
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&bytes.as_ref()[0..20]);
        hash
    }
}
