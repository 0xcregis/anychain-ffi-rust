use std::{convert::TryFrom, fmt::Display};

pub enum ChainType {
    Bitcoin,
    BitcoinTestnet,
    BitcoinCash,
    BitcoinCashTestnet,
    Litecoin,
    LitecoinTestnet,
    Dogecoin,
    DogecoinTestnet,
}

#[derive(Debug, Error)]
pub enum ChainTypeError {
    UnknownType(u32),
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
            _ => Err(ChainTypeError::UnknownType(type_code)),
        }
    }

    type Error = ChainTypeError;
}
