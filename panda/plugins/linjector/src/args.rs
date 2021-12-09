use once_cell::sync::OnceCell;
use panda::prelude::*;

static ELF_TO_INJECT: OnceCell<Vec<u8>> = OnceCell::new();

#[derive(PandaArgs)]
#[name = "linjector"] // plugin name
pub struct Args {
    #[arg(default = "guest_daemon")]
    pub guest_binary: String,

    #[arg(default = "[any]")]
    pub proc_name: String,

    #[arg(default = true)]
    pub require_root: bool,
}

lazy_static::lazy_static! {
    pub static ref ARGS: Args = Args::from_panda_args();
}

pub fn ensure_init() {
    lazy_static::initialize(&ARGS);
}

pub fn load_elf() {
    log::info!("Loading binary: {:?}", ARGS.guest_binary);
    ELF_TO_INJECT.get_or_init(|| std::fs::read(&ARGS.guest_binary).unwrap());
}

pub fn elf_to_inject() -> &'static [u8] {
    &ELF_TO_INJECT.get().expect("No elf file loaded")[..]
}

pub fn require_root() -> bool {
    ARGS.require_root
}

pub fn proc_name() -> &'static str {
    ARGS.proc_name.as_str()
}
