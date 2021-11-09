
use lzma_rs;
use serde_json;
use serde_json::{Value, Map};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize,Deserialize,Debug)]
pub struct VTypeBaseType {
    pub size: i64,
    pub signed: bool,
    pub kind: String,
    pub endian: String,
}

#[derive(Serialize,Deserialize,Debug)]
pub struct VTypeEnum {
    pub size: i64,
    pub base: String,
    pub constants: HashMap<String, i64>
}

#[derive(Serialize,Deserialize,Debug)]
pub struct VTypeSymbol {
    #[serde(rename = "type")]
    pub type_val: Option<Map<String, Value>>,
    pub address: u64,
    pub constant_data: Option<String>
}


#[derive(Serialize,Deserialize,Debug)]
pub struct VTypeStructField{
    #[serde(rename = "type")]
    pub type_val: Option<Map<String, Value>>,
    pub offset: i64,
    pub anonymous: Option<bool>
}

#[derive(Serialize,Deserialize,Debug)]
pub struct VTypeStruct{
    pub size: i64,
    pub fields: HashMap<String, VTypeStructField>,
    pub kind: String
}

#[derive(Serialize,Deserialize,Debug)]
pub struct SourceMetadata {
    pub kind: String,
    pub name: String,
    pub hash_type: String,
    pub hash_value: String
}

#[derive(Serialize,Deserialize,Debug)]
pub struct UnixMetadata{
    pub symbols: Vec<SourceMetadata>,
    pub types: Vec<SourceMetadata>
}

#[derive(Serialize,Deserialize,Debug)]
pub struct Producer{
    pub name: String,
    pub version: String
}


#[derive(Serialize,Deserialize,Debug)]
pub struct VTypeMetadata {
    pub linux: UnixMetadata,
    pub producer: Producer,
    pub format: String
}

#[derive(Serialize,Deserialize,Debug)]
pub struct VTypeJson{
    pub metadata: VTypeMetadata,
    pub base_types: HashMap<String,VTypeBaseType>,
    pub user_types: HashMap<String,VTypeStruct>,
    pub enums: HashMap<String,VTypeEnum>,
    pub symbols: HashMap<String,VTypeSymbol>,
}

impl VTypeJson{
    pub fn from_file(filename: &str) -> VTypeJson{
        let mut f = std::io::BufReader::new(std::fs::File::open(filename).unwrap());
        let mut decomp: Vec<u8> = Vec::new();
        lzma_rs::xz_decompress(&mut f, &mut decomp).unwrap();
        let s = String::from_utf8_lossy(&decomp);
        serde_json::from_str(&s).unwrap()
    }
    
    pub fn enum_from_name(self: &VTypeJson, name: &str) -> Option<&VTypeEnum> {
        self.enums.get(name)
    }

    pub fn base_type_from_name(self: &VTypeJson, name: &str) -> Option<&VTypeBaseType> {
        self.base_types.get(name)
    }
    
    pub fn symbol_from_name(self: &VTypeJson, name: &str) -> Option<&VTypeSymbol> {
        self.symbols.get(name)
    }
    
    pub fn type_from_name(self: &VTypeJson, name: &str) -> Option<&VTypeStruct> {
        self.user_types.get(name)
    }
}