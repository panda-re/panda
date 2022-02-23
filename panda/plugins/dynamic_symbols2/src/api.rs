use crate::symbol_manager::SymbolManager;
use panda::prelude::*;

lazy_static! {
    pub(crate) static ref SYMBOL_MANAGER: SymbolManager = SymbolManager::new();
}

extern "C" fn hook_symbol() {}

extern "C" fn hook_library_offset() {}
