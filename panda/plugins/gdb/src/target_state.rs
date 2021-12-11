use panda::prelude::*;

use std::sync::{RwLock, Mutex, atomic::{AtomicBool, AtomicUsize, Ordering}};
use std::sync::mpsc::{channel, Sender, Receiver};
use std::collections::HashSet;

pub struct State {
    single_step: AtomicBool,
    exit_kernel: AtomicBool,
    breakpoints: RwLock<HashSet<target_ptr_t>>,
    cpu: Mutex<Option<usize>>,
    pc: AtomicUsize,
    pid: AtomicUsize,
    pub brk: Signal<BreakStatus>,
    pub cont: Signal<()>,
}

#[derive(Copy, Clone, Debug)]
pub enum BreakStatus {
    Break,
    Exit
}

impl State {
    fn new() -> Self {
        State {
            single_step: AtomicBool::new(false),
            exit_kernel: AtomicBool::new(false),
            breakpoints: RwLock::new(HashSet::new()),
            brk: Signal::new(),
            cont: Signal::new(),
            cpu: Mutex::new(None),
            pc: AtomicUsize::new(0),
            pid: AtomicUsize::new(0),
        }
    }

    pub fn breakpoints_contain(&self, pc: target_ptr_t) -> bool {
        self.breakpoints
            .read()
            .unwrap()
            .contains(&pc)
    }

    pub fn exiting_kernel(&self) -> bool {
        self.exit_kernel.load(Ordering::SeqCst)
    }

    #[cfg(feature = "x86_64")]
    pub fn exited_kernel(&self, pc: target_ptr_t) -> bool {
        //const MASK: target_ptr_t = 0xffffff000000;
        //const VALUE: target_ptr_t = 0x555555000000;

        self.exiting_kernel() && (0x555555554000..0x55555555c000).contains(&pc)
        //self.exiting_kernel() && (pc & MASK == VALUE)
    }

    #[cfg(not(feature = "x86_64"))]
    pub fn exited_kernel(&self, pc: target_ptr_t) -> bool {
        self.exiting_kernel()
    }

    pub fn set_exit_kernel(&self) {
        self.exit_kernel.store(true, Ordering::SeqCst)
    }

    pub fn unset_exit_kernel(&self) {
        self.exit_kernel.store(false, Ordering::SeqCst)
    }

    pub fn single_stepping(&self) -> bool {
        self.single_step
            .load(Ordering::SeqCst)
    }

    pub fn start_single_stepping(&self) {
        self.single_step
            .store(true, Ordering::SeqCst)
    }

    pub fn stop_single_stepping(&self) {
        self.single_step
            .store(false, Ordering::SeqCst)
    }

    // TODO: figure out some way to ensure CPUState doesn't outlive the breakpoint
    // RefCell maybe?
    pub fn wait_for_cpu(&self) -> &'static mut CPUState {
        loop {
            {
                if let Some(_) = *self.cpu.lock().unwrap() {
                    break
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(30));
        }

        unsafe {
            std::mem::transmute(self.cpu.lock().unwrap().unwrap())
        }
    }

    pub fn set_cpu(&self, cpu: &mut CPUState) {
        let mut stored_cpu = self.cpu.lock().unwrap();

        *stored_cpu = Some(cpu as *mut _ as usize);
    }

    pub fn unset_cpu(&self) {
        *self.cpu.lock().unwrap() = None;
    }
    
    pub fn set_pc(&self, pc: target_ptr_t) {
        self.pc.store(pc as usize, Ordering::SeqCst);
    }
    
    pub fn get_pc(&self) -> target_ptr_t {
        self.pc.load(Ordering::SeqCst) as target_ptr_t
    }

    pub fn add_breakpoint(&self, pc: target_ptr_t) -> bool {
        self.breakpoints
            .write()
            .unwrap()
            .insert(pc)
    }

    pub fn remove_breakpoint(&self, pc: target_ptr_t) -> bool {
        self.breakpoints
            .write()
            .unwrap()
            .remove(&pc)
    }

    pub fn is_pid_set(&self) -> bool {
        self.pid.load(Ordering::SeqCst) != 0
    }

    pub fn set_pid(&self, pid: target_ulong) {
        self.pid.store(pid as usize, Ordering::SeqCst);
    }

    pub fn unset_pid(&self) {
        self.pid.store(0, Ordering::SeqCst);
    }

    pub fn get_pid(&self) -> Option<target_ulong> {
        match self.pid.load(Ordering::SeqCst) {
            0 => None,
            x => Some(x as _)
        }
    }
}

pub struct Signal<T> {
    recv: Mutex<Receiver<T>>,
    send: Mutex<Sender<T>>
}

impl<T: Sized> Signal<T> {
    fn new() -> Self {
        let (send, recv) = channel();
        let (send, recv) = (Mutex::new(send), Mutex::new(recv));
        Self { send, recv }
    }

    pub fn wait_for(&self) -> T {
        self.recv
            .lock()
            .unwrap()
            .recv()
            .unwrap()
    }

    pub fn signal(&self, x: T) {
        self.send
            .lock()
            .unwrap()
            .send(x)
            .unwrap()
    }
}

lazy_static::lazy_static!{
    pub static ref STATE: State = State::new();
}
