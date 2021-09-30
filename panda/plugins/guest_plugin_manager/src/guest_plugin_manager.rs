use panda::prelude::*;

use std::convert::TryFrom;

mod hyp_regs;
use hyp_regs::{get_hyp_reg, set_hyp_reg};

mod interface;
use interface::hci::{hyp_error, hyp_read, hyp_start, hyp_stop, hyp_write};

const MAGIC: usize = 0x1337c0d3;

#[derive(Copy, Clone)]
pub enum HcCmd {
    Start = 1, /* start new action */
    Stop,      /* stop action */
    Read,      /* read buffer from hypervisor */
    Write,     /* write buffer TO hypervisor*/
    Error,     /* report error to hypervisor*/
}

impl TryFrom<usize> for HcCmd {
    type Error = ();

    fn try_from(value: usize) -> Result<Self, ()> {
        match value {
            1 => Ok(HcCmd::Start),
            2 => Ok(HcCmd::Stop),
            3 => Ok(HcCmd::Read),
            4 => Ok(HcCmd::Write),
            5 => Ok(HcCmd::Error),
            _ => Err(()),
        }
    }
}

#[panda::guest_hypercall]
fn hypercall_handler(cpu: &mut CPUState) -> bool {
    let magicval = get_hyp_reg(cpu, 0);
    if magicval == MAGIC {
        let action = get_hyp_reg(cpu, 1);
        let channel_id = get_hyp_reg(cpu, 2) as u32;
        let first_arg = get_hyp_reg(cpu, 3);
        let second_arg = get_hyp_reg(cpu, 4);

        let retval = match HcCmd::try_from(action) {
            Ok(HcCmd::Start) => {
                hyp_start(cpu, channel_id, first_arg, second_arg)
            }
            Ok(HcCmd::Write) => {
                hyp_write(cpu, channel_id, first_arg, second_arg)
            }
            Ok(HcCmd::Read) => hyp_read(cpu, channel_id, first_arg, second_arg),
            Ok(HcCmd::Stop) => hyp_stop(cpu, channel_id, first_arg, second_arg),
            Ok(HcCmd::Error) => {
                hyp_error(cpu, channel_id, first_arg, second_arg)
            }
            _ => None,
        };

        if let Some(retval) = retval {
            set_hyp_reg(cpu, 0, retval);
        }
    }
    true
}

#[panda::init]
fn init(_: &mut PluginHandle) -> bool {
    true
}

#[panda::uninit]
fn exit(_: &mut PluginHandle) {
    println!("Exiting");
}
