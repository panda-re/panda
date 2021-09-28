use object::{Object, ObjectSection};
use once_cell::sync::OnceCell;
use panda::mem::{virtual_memory_read, virtual_memory_write};
use panda::plugins::hooks::Hook;
use panda::plugins::proc_start_linux::{AuxvValues, PROC_START_LINUX};
use panda::prelude::*;
use panda::regs::{get_pc, get_reg, set_reg, Reg};
use std::cmp::min;
use std::convert::TryFrom;
use std::sync::atomic::{AtomicUsize, Ordering};

static POINTERS: OnceCell<[target_ulong; 3]> = OnceCell::new();
static POINTERS_READ: AtomicUsize = AtomicUsize::new(0);
static SAVED_BUF: OnceCell<Vec<u8>> = OnceCell::new();
static ELF_TO_INJECT: OnceCell<Vec<u8>> = OnceCell::new();
static ELF_READ_POS: AtomicUsize = AtomicUsize::new(0);

const MAGIC: usize = 0x10adc0d3;
const X86_REG_ORDER: [Reg; 4] = [Reg::RAX, Reg::RBX, Reg::RCX, Reg::RDX];
const ELF_PATH: &str = "/home/luke/workspace/igloo/pie_idea/rusty_shell/target/i686-unknown-linux-musl/release/rusty_shell";

#[derive(Copy, Clone)]
pub enum HcCmd {
    Noop = 0,
    Start,         /* start new action */
    Stop,          /* stop action */
    Read,          /* read buffer from hypervisor */
    Write,         /* write buffer TO hypervisor*/
    Error,         /* report error to hypervisor*/
    ConditionalOp, /* ask the hypervisor if op should be completed*/
    NextStateMachine, /* ask the hypervisor manager to move to the next
                   state machine*/
}

impl TryFrom<usize> for HcCmd {
    type Error = ();

    fn try_from(value: usize) -> Result<Self, ()> {
        match value {
            0 => Ok(HcCmd::Noop),
            1 => Ok(HcCmd::Start),
            2 => Ok(HcCmd::Stop),
            3 => Ok(HcCmd::Read),
            4 => Ok(HcCmd::Write),
            5 => Ok(HcCmd::Error),
            6 => Ok(HcCmd::ConditionalOp),
            7 => Ok(HcCmd::NextStateMachine),
            _ => Err(()),
        }
    }
}

fn parse_file_data(file_bytes: &[u8]) -> (&[u8], usize, usize) {
    let obj_file = object::File::parse(file_bytes).expect("Couldn't parse ELF");
    let text_section = obj_file
        .section_by_name(".text")
        .expect("Couldn't locate .text section");
    let text_data = text_section.data().unwrap();
    let offset = text_section.address() - obj_file.entry();
    let section_size = text_section.size();
    (text_data, offset as usize, section_size as usize)
}

#[panda::hook]
fn inject_hook(
    cpu: &mut CPUState,
    _tb: &mut TranslationBlock,
    _exit_code: u8,
    hook: &mut Hook,
) {
    let inject_bytes = include_bytes!("./injectables/injector");
    let (text_data, _offset, _section_size) =
        parse_file_data(&inject_bytes[..]);
    let pc = panda::regs::get_pc(cpu);
    virtual_memory_write(cpu, pc, text_data);
    hook.enabled = false;
}

fn get_hyp_reg(cpu: &mut CPUState, num: usize) -> usize {
    let reg_to_read = X86_REG_ORDER[num];
    get_reg(cpu, reg_to_read) as usize
}

fn hyp_start(_cpu: &mut CPUState, arg1: usize, _arg2: usize) -> Option<usize> {
    inject_hook::hook().after_block_exec().at_addr(arg1 as u64);
    None
}

fn hyp_write(cpu: &mut CPUState, arg1: usize, arg2: usize) -> Option<usize> {
    ELF_TO_INJECT.get_or_init(|| std::fs::read(ELF_PATH).unwrap());
    let buf_to_write = arg1;
    let size_requested = arg2;

    let read_pos = ELF_READ_POS.load(Ordering::SeqCst);
    let buf_size = ELF_TO_INJECT.get().expect("").len();
    if read_pos < buf_size {
        let lower = read_pos;
        let upper = min(buf_size, read_pos + size_requested);
        let data_to_write = &ELF_TO_INJECT.get().expect("")[lower..upper];
        virtual_memory_write(cpu, buf_to_write as u64, data_to_write);
        ELF_READ_POS.fetch_add(upper - lower, Ordering::SeqCst);
        Some(upper - lower)
    } else {
        None
    }
}

fn hyp_read(cpu: &mut CPUState, arg1: usize, _arg2: usize) -> Option<usize> {
    println!("Got to read with {:#x}", arg1);
    assert!(arg1 != 0, "arg1 is a fork return 0 is the child");
    let ptr_pos = POINTERS_READ.load(Ordering::SeqCst);
    let pointers = POINTERS.get().unwrap();
    let pc = get_pc(cpu);

    if ptr_pos <= pointers.len() {
        if ptr_pos == pointers.len() {
            virtual_memory_write(cpu, pc, SAVED_BUF.get().unwrap());
            None
        } else {
            POINTERS_READ.fetch_add(1, Ordering::SeqCst);
            Some(pointers[ptr_pos] as usize)
        }
    } else {
        None
    }
}

fn hyp_stop(cpu: &mut CPUState, arg1: usize, _arg2: usize) -> Option<usize> {
    if POINTERS_READ.load(Ordering::SeqCst) == POINTERS.get().unwrap().len() {
        virtual_memory_write(cpu, arg1 as u64, "\x01\x02\x03\x04".as_bytes());
    }
    None
}

#[panda::guest_hypercall]
fn hypercall_handler(cpu: &mut CPUState) -> bool {
    let magicval = get_hyp_reg(cpu, 0);
    if magicval == MAGIC {
        let action = get_hyp_reg(cpu, 1);
        let first_arg = get_hyp_reg(cpu, 2);
        let second_arg = get_hyp_reg(cpu, 3);

        let retval = match HcCmd::try_from(action) {
            Ok(HcCmd::Start) => hyp_start(cpu, first_arg, second_arg),
            Ok(HcCmd::Write) => hyp_write(cpu, first_arg, second_arg),
            Ok(HcCmd::Read) => hyp_read(cpu, first_arg, second_arg),
            Ok(HcCmd::Stop) => hyp_stop(cpu, first_arg, second_arg),
            _ => None,
        };

        match retval {
            Some(p) => set_reg(cpu, Reg::RAX, p as u64),
            None => (),
        }
    }
    true
}

#[panda::hook]
fn entry_hook(
    cpu: &mut CPUState,
    _tb: &mut TranslationBlock,
    _exit_code: u8,
    hook: &mut Hook,
) {
    let inject_bytes = include_bytes!("./injectables/tiny_mmap");
    let (text_data, offset, section_size) = parse_file_data(&inject_bytes[..]);
    assert_eq!(
        offset, 0,
        "get better shellcode. why is there another function?"
    );
    let pc = get_pc(cpu);
    SAVED_BUF
        .set(
            virtual_memory_read(cpu, pc, section_size as usize)
                .expect("failed to read buf. you might need a smaller injector or another stage"),
        )
        .unwrap();
    virtual_memory_write(cpu, pc, text_data);
    println!("Replacing bytes at PC with tiny_mmap");

    hook.enabled = false;
}

extern "C" fn handle_proc_start(
    _cpu: &mut CPUState,
    _tb: &mut TranslationBlock,
    auxv: &AuxvValues,
) {
    if true {
        // auxv.euid == 0 for root only
        println!("accepting new proc with euid {}", auxv.euid);
        // get pointers to values for re-starting process
        let execfn_ptr = auxv.execfn_ptr;
        let argv_ptr_ptr = auxv.argv_ptr_ptr;
        let env_ptr_ptr = auxv.env_ptr_ptr;

        // in your callback
        POINTERS
            .set([execfn_ptr, argv_ptr_ptr, env_ptr_ptr])
            .unwrap();

        // set a
        entry_hook::hook().after_block_exec().at_addr(auxv.entry);

        PROC_START_LINUX.remove_callback_on_rec_auxv(handle_proc_start);
    }
}

#[panda::init]
fn init(_: &mut PluginHandle) -> bool {
    println!("Initialized!");
    PROC_START_LINUX.add_callback_on_rec_auxv(handle_proc_start);
    true
}

#[panda::uninit]
fn exit(_: &mut PluginHandle) {
    println!("Exiting");
}
