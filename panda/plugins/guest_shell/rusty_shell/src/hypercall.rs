use std::{io::Write, marker::PhantomData};

const HC_MAGIC: usize = 0x666;

#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum HcCmd {
    Noop = 0,
    Start,             /* start new action */
    Stop,              /* stop action */
    Read,              /* read buffer from hypervisor */
    Write,             /* write buffer TO hypervisor*/
    Error,             /* report error to hypervisor*/
    ConditionalOp,     /* ask the hypervisor if op should be completed*/
    NextStateMachine,  /* ask the hypervisor manager to move to the next
                            state machine*/
}

pub struct HyperCall<'a> {
    cmd : HcCmd,
    args: Vec<usize>,
    lifetime: PhantomData<&'a ()>,
}

impl HyperCall<'static> {
    pub fn new(cmd: HcCmd) -> Self {
        Self {
            cmd,
            args: vec![0; 2],
            lifetime: PhantomData,
        }
    }
}

#[allow(dead_code)]
impl<'a> HyperCall<'a> {
    pub fn arg(&mut self, arg: usize) -> &mut Self {
        self.args.push(arg);
        self
    }

    pub fn from_string(command: HcCmd, s: &'a str) -> HyperCall<'a> {
        Self {
            cmd: command,
            args: vec![
                s.as_ptr() as usize,
                s.len(),
            ],
            lifetime: PhantomData,
        }
    }

    pub fn from_buf(command: HcCmd, buf: &'a [u8]) -> HyperCall<'a> {
        Self {
            cmd: command,
            args: vec![
                buf.as_ptr() as usize,
                buf.len(),
            ],
            lifetime: PhantomData,
        }
    }

    pub fn from_mut_buf(command: HcCmd, buf: &'a mut [u8]) -> HyperCall<'a> {
        Self {
            cmd: command,
            args: vec![
                buf.as_ptr() as usize,
                buf.len(),
            ],
            lifetime: PhantomData,
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn call(&mut self) -> usize {
        let ret_val;

        while self.args.len() < 2 {
            self.args.push(0);
        }

        unsafe {
            asm!(
                "mov eax, {hc_magic}",
                "mov ebx, {command:e}",
                "cpuid",
                hc_magic = const HC_MAGIC,
                command = in(reg) self.cmd as u32,
                in("ecx") self.args[0],
                in("edx") self.args[1],
                out("eax") ret_val,
            );
        }

        ret_val
    }
}

struct HyperWriter;

impl Write for HyperWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        HyperCall::from_buf(HcCmd::Write, buf).call();

        Ok(buf.len())
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
