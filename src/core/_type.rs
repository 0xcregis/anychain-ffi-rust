use std::{convert::TryFrom, fmt::Display};

pub(crate) enum CurveType {
    Secp256k1,
    // Ed25519,
}

pub(crate) enum ChainType {
    Bitcoin,
    BitcoinTestnet,
    BitcoinCash,
    BitcoinCashTestnet,
    Litecoin,
    LitecoinTestnet,
    Dogecoin,
    DogecoinTestnet,
    Ethereum,
    Goerli,
    Sepolia,
    Polygon,
    Mumbai,
    Arbitrum,
    ArbitrumGoerli,
    Optimism,
    OptimismGoerli,
    OpBnb,
    OpBnbTestnet,
    Avalanche,
    AvalancheTestnet,
    Base,
    BaseGoerli,
    EthereumClassic,
    Kotti,
    HuobiEco,
    HuobiEcoTestnet,
    BinanceSmartChain,
    BinanceSmartChainTestnet,
    Okex,
    OkexTestnet,
    Tron,
    TronTestnet,
}

#[derive(Debug, Error)]
pub enum ChainTypeError {
    UnknownType(u32),
}

impl ChainType {
    pub(crate) fn curve(&self) -> CurveType {
        CurveType::Secp256k1
        // match self {
        //     ChainType::Solana | ChainType::SolanaTestnet => CurveType::Ed25519,
        //     _ => CurveType::Secp256k1,
        // }
    }
}

impl Display for ChainTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownType(code) => write!(f, "unknown chain type :{}", code),
        }
    }
}

impl TryFrom<u32> for ChainType {
    fn try_from(type_code: u32) -> Result<Self, Self::Error> {
        match type_code {
            0 => Ok(Self::Bitcoin),
            1 => Ok(Self::BitcoinTestnet),
            5 => Ok(Self::BitcoinCash),
            51 => Ok(Self::BitcoinCashTestnet),
            2 => Ok(Self::Litecoin),
            21 => Ok(Self::LitecoinTestnet),
            3 => Ok(Self::Dogecoin),
            31 => Ok(Self::DogecoinTestnet),
            60 => Ok(Self::Ethereum),                   // chain id = 1
            6001 => Ok(Self::Goerli),                   // chain id = 5
            6002 => Ok(Self::Sepolia),                  // chain id = 11155111
            61 => Ok(Self::EthereumClassic),            // chain id = 61
            6101 => Ok(Self::Kotti),                    // chain id = 6
            62 => Ok(Self::Polygon),                    // chain id = 137
            6201 => Ok(Self::Mumbai),                   // chain id = 80001
            63 => Ok(Self::Arbitrum),                   // chain id = 42161
            6301 => Ok(Self::ArbitrumGoerli),           // chain id = 421613
            64 => Ok(Self::Optimism),                   // chain id = 10
            6401 => Ok(Self::OptimismGoerli),           // chain id = 420
            65 => Ok(Self::Avalanche),                  // chain id = 43114
            6501 => Ok(Self::AvalancheTestnet),         // chain id = 43113
            66 => Ok(Self::Base),                       // chain id = 8453
            6601 => Ok(Self::BaseGoerli),               // chain id = 84531
            67 => Ok(Self::OpBnb),                      // chain id = 204
            6701 => Ok(Self::OpBnbTestnet),             // chain id = 5611
            2509 => Ok(Self::HuobiEco),                 // chain id = 128
            2609 => Ok(Self::HuobiEcoTestnet),          // chain id = 256
            2510 => Ok(Self::BinanceSmartChain),        // chain id = 56
            2610 => Ok(Self::BinanceSmartChainTestnet), // chain id = 97
            2511 => Ok(Self::Okex),                     // chain id = 66
            2611 => Ok(Self::OkexTestnet),              // chain id = 65
            195 => Ok(Self::Tron),
            198 => Ok(Self::TronTestnet),
            _ => Err(ChainTypeError::UnknownType(type_code)),
        }
    }

    type Error = ChainTypeError;
}
