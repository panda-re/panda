use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    fs::{self, File},
    io::BufReader,
    path::Path,
};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct VolatilityBaseType {
    pub size: i64,
    pub signed: bool,
    pub kind: String,
    pub endian: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct VolatilityEnum {
    pub size: i64,
    pub base: String,
    pub constants: HashMap<String, i64>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct VolatilitySymbol {
    #[serde(rename = "type")]
    pub type_val: Option<VolatilityType>,
    pub address: u64,
    pub constant_data: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum VolatilityType {
    Base {
        name: String,
    },

    Array {
        count: u64,
        subtype: Box<VolatilityType>,
    },

    Pointer {
        subtype: Box<VolatilityType>,
    },

    Struct {
        name: String,
    },

    Enum {
        name: String,
    },

    Union {
        name: String,
    },

    Bitfield {
        bit_position: i64,
        bit_length: u64,

        #[serde(rename = "type")]
        base_type: Box<VolatilityType>,
    },

    Function,
}

impl fmt::Display for VolatilityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VolatilityType::Base { name } => f.write_str(&name),
            VolatilityType::Array { count, subtype } => {
                write!(f, "{}[{}]", subtype.to_string(), count)
            }
            VolatilityType::Pointer { subtype } => write!(f, "{}*", subtype),
            VolatilityType::Struct { name } => write!(f, "struct {}", name),
            VolatilityType::Enum { name } => write!(f, "enum {}", name),
            VolatilityType::Union { name } => write!(f, "union {}", name),
            VolatilityType::Bitfield {
                bit_position,
                bit_length,
                base_type,
            } => write!(
                f,
                "(bitfield {}[{}..{}])",
                base_type,
                bit_position,
                (*bit_position as u64) + bit_length
            ),
            VolatilityType::Function => write!(f, "func_ptr"),
        }
    }
}

impl VolatilityType {
    pub fn to_string(&self) -> String {
        match self {
            VolatilityType::Base { name } => name.clone(),
            VolatilityType::Array { count, subtype } => {
                format!("{}[{}]", subtype.to_string(), count)
            }
            VolatilityType::Pointer { subtype } => format!("{}*", subtype.to_string()),
            VolatilityType::Struct { name: _ } => todo!(),
            VolatilityType::Enum { name: _ } => todo!(),
            VolatilityType::Union { name: _ } => todo!(),
            VolatilityType::Bitfield {
                bit_position: _,
                bit_length: _,
                base_type: _,
            } => todo!(),
            VolatilityType::Function => todo!(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct VolatilityStructField {
    #[serde(rename = "type")]
    pub type_val: Option<VolatilityType>,
    pub offset: i64,
    pub anonymous: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct VolatilityStruct {
    pub size: i64,
    pub fields: BTreeMap<String, VolatilityStructField>,
    pub kind: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SourceMetadata {
    pub kind: String,
    pub name: String,
    pub hash_type: String,
    pub hash_value: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UnixMetadata {
    pub symbols: Vec<SourceMetadata>,
    pub types: Vec<SourceMetadata>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Producer {
    pub name: String,
    pub version: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VolatilityMetadata {
    pub linux: UnixMetadata,
    pub producer: Producer,
    pub format: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VolatilityJson {
    pub metadata: VolatilityMetadata,
    pub base_types: HashMap<String, VolatilityBaseType>,
    pub user_types: HashMap<String, VolatilityStruct>,
    pub enums: HashMap<String, VolatilityEnum>,
    pub symbols: HashMap<String, VolatilitySymbol>,
}

impl VolatilityJson {
    pub fn from_compressed_file(filename: impl AsRef<Path>) -> VolatilityJson {
        //pub fn from_compressed_file(filename: std::fs::File) -> VolatilityJson {
        let file = File::open(filename).unwrap();
        if file.metadata().unwrap().len() == 0 {
            panic!("cosi volatility profile empty");
        }

        let mut f = BufReader::new(file);
        let mut decomp = Vec::new();
        lzma_rs::xz_decompress(&mut f, &mut decomp).unwrap();
        let s = String::from_utf8_lossy(&decomp);
        serde_json::from_str(&s).unwrap()
    }

    pub fn from_file(filename: impl AsRef<Path>) -> VolatilityJson {
        let contents = fs::read_to_string(filename).unwrap();
        serde_json::from_str(&contents).unwrap()
    }

    pub fn enum_from_name(&self, name: &str) -> Option<&VolatilityEnum> {
        self.enums.get(name)
    }

    pub fn base_type_from_name(&self, name: &str) -> Option<&VolatilityBaseType> {
        self.base_types.get(name)
    }

    pub fn symbol_from_name(&self, name: &str) -> Option<&VolatilitySymbol> {
        self.symbols.get(name)
    }

    pub fn type_from_name(&self, name: &str) -> Option<&VolatilityStruct> {
        self.user_types.get(name)
    }
}
