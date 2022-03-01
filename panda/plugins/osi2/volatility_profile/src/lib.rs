use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{
    collections::HashMap,
    fs::{self, File},
    io::BufReader,
    path::Path,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct VolatilityBaseType {
    pub size: i64,
    pub signed: bool,
    pub kind: String,
    pub endian: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VolatilityEnum {
    pub size: i64,
    pub base: String,
    pub constants: HashMap<String, i64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VolatilitySymbol {
    #[serde(rename = "type")]
    pub type_val: Option<Map<String, Value>>,
    pub address: u64,
    pub constant_data: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VolatilityStructField {
    #[serde(rename = "type")]
    pub type_val: Option<Map<String, Value>>,
    pub offset: i64,
    pub anonymous: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VolatilityStruct {
    pub size: i64,
    pub fields: HashMap<String, VolatilityStructField>,
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
        let mut f = BufReader::new(File::open(filename).unwrap());
        let mut decomp = Vec::new();
        lzma_rs::xz_decompress(&mut f, &mut decomp).unwrap();
        let s = String::from_utf8_lossy(&decomp);
        serde_json::from_str(&s).unwrap()
    }

    pub fn from_file(filename: impl AsRef<Path>) -> VolatilityJson {
        let contents = fs::read_to_string(filename).unwrap();
        serde_json::from_str(&contents).unwrap()
    }

    pub fn enum_from_name(self: &VolatilityJson, name: &str) -> Option<&VolatilityEnum> {
        self.enums.get(name)
    }

    pub fn base_type_from_name(self: &VolatilityJson, name: &str) -> Option<&VolatilityBaseType> {
        self.base_types.get(name)
    }

    pub fn symbol_from_name(self: &VolatilityJson, name: &str) -> Option<&VolatilitySymbol> {
        self.symbols.get(name)
    }

    pub fn type_from_name(self: &VolatilityJson, name: &str) -> Option<&VolatilityStruct> {
        self.user_types.get(name)
    }
}
