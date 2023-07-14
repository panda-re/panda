use panda::prelude::*;
use panda::plugins::osi::OSI;
use std::cell::RefCell;
use std::sync::Mutex;
use std::time::{SystemTime, Duration};
use std::collections::HashMap;
use std::convert::TryFrom;
use once_cell::sync::OnceCell;

#[derive(PandaArgs)]
#[name = "osi"]
struct OsiArgs {
}

#[derive(PandaArgs)]
#[name = "asidstory_rs"]
struct AsidstoryArgs {
    #[arg(default = 100)]
    width: u32,
    summary_mode: bool,
}

enum Mode {
    ProcessUnknown,
    ProcessSuspicious,
    ProcessKnown,
}

//static mut NEXT_CHECK_TIME: SystemTime = SystemTime::UNIX_EPOCH;

thread_local!(static NEXT_CHECK_TIME: RefCell<SystemTime>  = RefCell::new(SystemTime::UNIX_EPOCH));
thread_local!(static KERNEL_COUNT: RefCell<u64>  = RefCell::new(0));
thread_local!(static USER_COUNT: RefCell<u64>  = RefCell::new(0));
thread_local!(static INSTR_COUNT: RefCell<u64> = RefCell::new(0));
thread_local!(static MAX_INSTR: RefCell<u32> = RefCell::new(0));
thread_local!(static SCALE: RefCell<f64> = RefCell::new(0.0));
thread_local!(static PROCESS_MODE: RefCell<Mode> = RefCell::new(Mode::ProcessUnknown));
thread_local!(static ASID_AT_ASID_CHANGED: RefCell<target_ulong> = RefCell::new(0));

//thread_local!(static NUM_CELLS: RefCell<u32> = RefCell::new(0));
//thread_local!(static ASID_COUNT: RefCell<HashMap<target_ulong, u64>> = RefCell::new(HashMap::new()));

static mut ASID_COUNT: OnceCell<Mutex<HashMap<target_ulong, u64>>> = OnceCell::new();
static mut NUM_CELLS: u32 = 0;
//lazy_static! {
//    static ref ASID_COUNT: Mutex<HashMap<target_ulong, u64>> = Mutex::new(HashMap::new());
//}

    //NEXT_CHECK_TIME.with(|text| {
    //    let t = SystemTime::now();
    //    let dur = t.duration_since(*text.borrow());
    //    match dur {
    //        Ok(n) => println!("epoch was {} seconds ago", n.as_secs()),
    //        Err(_) => panic!("time was before epoch"),
    //    };
    //});

fn spit_asidstory() {

}


#[panda::before_block_exec]
fn bbe(cpu: &mut CPUState, tb: &mut TranslationBlock){
//    unsafe {
//        println!("bbe: num_cells: {}", NUM_CELLS);
//        //println!("scale {}", scale.borrow());
//        //println!("num_cells: {}, max_instr: {}", num_cells.borrow(), max_instr.borrow());
//    }




    unsafe {
        if !(panda::sys::rr_control.mode == panda::sys::RR_mode_RR_REPLAY) {
            NEXT_CHECK_TIME.with(|next_check_time| {
                let current_time = SystemTime::now();
                let difference = current_time.duration_since(*next_check_time.borrow());
                match difference {
                    Ok(_) => {
                        spit_asidstory();
                        *next_check_time.borrow_mut() = current_time.checked_add(Duration::from_secs(1)).expect("couldn't increment time counter");
                    },
                    Err(_) => {},
                }
            });

            INSTR_COUNT.with(|count| {
                *count.borrow_mut() += u64::from(tb.icount);
            })
        }
    }

    if panda::in_kernel_mode(cpu) {
        KERNEL_COUNT.with(|kernel_count| {
            *kernel_count.borrow_mut() += 1;
            //println!("kernel count is now: {}", *kernel_count.borrow());
        })
    } else {
        USER_COUNT.with(|user_count| {
            *user_count.borrow_mut() += 1;
            //println!("user count is now: {}", *user_count.borrow());
        })
    }

    let current_asid = panda::current_asid(cpu);

    unsafe {
        //asid_count.entry(current_asid).and_modify(|counter| *counter += 1).or_insert(1);
        ASID_COUNT.get_mut().expect("couldn't get asid_counts").lock().unwrap().entry(current_asid).and_modify(|counter| *counter += 1).or_insert(1);
    }

    unsafe {
        if panda::sys::rr_control.mode == panda::sys::RR_mode_RR_REPLAY {
            MAX_INSTR.with(|max_instr| {
                if *max_instr.borrow() == 0 {
                    *max_instr.borrow_mut() = u32::try_from(panda::sys::replay_get_total_num_instructions()).expect("couldn't convert total instructions to u32");
                }

                SCALE.with(|scale| {
                    *scale.borrow_mut() = f64::from(NUM_CELLS) / f64::from(max_instr.borrow().clone());
                    println!("scale {}", scale.borrow());
                })
            })

        } else {        //if live
            MAX_INSTR.with(|max_instr| {
                INSTR_COUNT.with(|instr_count| {
                    *max_instr.borrow_mut() = u32::try_from(instr_count.borrow().clone()).expect("couldn't convert instr_count to u32");
                });

                SCALE.with(|scale| {
                    *scale.borrow_mut() = f64::from(NUM_CELLS) / f64::from(max_instr.borrow().clone());
                    //println!("scale {}", scale.borrow());
                    //println!("num_cells: {}, max_instr: {}", NUM_CELLS, max_instr.borrow());
                });
            });
        }
    }

}

fn get_instr_count() -> u64 {
    unsafe {
        if panda::sys::rr_control.mode == panda::sys::RR_mode_RR_REPLAY {
            return u64::try_from(panda::sys::rr_get_guest_instr_count_external()).expect("couldn't convert rr guest instr count to u64");
        } else {
            INSTR_COUNT.with(|instr_count| {
                return instr_count.borrow().clone();
            })
        }
    }
}

fn save_proc_range(num: u64) {

}

#[panda::asid_changed]
fn on_asid_change(_cpu: &mut CPUState, _old_asid: target_ptr_t, new_asid: target_ptr_t) -> bool {
    if new_asid == 0 {
        return false;
    }

    let curr_instr = get_instr_count();

    PROCESS_MODE.with(|process_mode| {
        match *process_mode.borrow() {
            Mode::ProcessKnown => {
                println!("process was known for last asid interval");
                save_proc_range(curr_instr-100);

                //if not pandalog
                    //if in replay
            },
            _ => println!("process was not known for last asid interval"),
        }
    });

    PROCESS_MODE.with(|process_mode| {
        *process_mode.borrow_mut() = Mode::ProcessUnknown;
    });

    ASID_AT_ASID_CHANGED.with(|asid_at_asid_changed| {
        *asid_at_asid_changed.borrow_mut() = new_asid;
    });

    println!("asid_changed: process mode unknown");

    return false;
}

#[panda::on_sys::execve_enter]
fn on_execve(cpu: &mut CPUState, _pc: SyscallPc, filename: u64, _argv: u64, _envp: u64, ) {
    let filename = &cpu.mem_read_string(filename);
    println!("Entering execve -- filename = {}", filename);
}

#[panda::on_sys::execveat_enter]
fn on_execveat(cpu: &mut CPUState, _pc: SyscallPc, _dirfd: i32, filename: u64, _argv: u64, _envp: u64, _flags: i32, ) {
    let filename = &cpu.mem_read_string(filename);
    println!("Entering execve -- filename = {}", filename);
}

#[panda::init]
fn init(_: &mut PluginHandle) -> bool {

    let osi_args = OsiArgs::from_panda_args();
    panda::require_plugin(&osi_args);

    let args = AsidstoryArgs::from_panda_args();

    println!("Initializing... width: {}, summary mode: {}", args.width, args.summary_mode);

    NEXT_CHECK_TIME.with(|next_check_time| {
    let t = SystemTime::now();
    *next_check_time.borrow_mut() = t.checked_add(Duration::from_secs(1)).expect("couldn't increment time counter");
    //let t = SystemTime::now();
    //let dur = t.duration_since(*text);
    //match dur {
    //    Ok(n) => println!("epoch was {} seconds ago", n.as_secs()),
    //    Err(_) => panic!("time was before epoch"),
    //};
    });


    unsafe {
        NUM_CELLS = args.width;
    }

    unsafe {
        println!("num_cells: {}", NUM_CELLS);
    }

    unsafe{
        ASID_COUNT.get_or_init(|| {
            let m: HashMap<target_ulong, u64> = HashMap::new();
            Mutex::new(m)
        });
    }


    println!("Initialized!");
    return true;
}

#[panda::uninit]
fn exit(_: &mut PluginHandle) {

    unsafe {
        println!("asid counts: ");
        let m = ASID_COUNT.get().expect("coundn't get asid_counts").lock().unwrap();
        println!("{:?}", m);
    }
    println!("Exiting");
}


