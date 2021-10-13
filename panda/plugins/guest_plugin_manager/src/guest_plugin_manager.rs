use panda::prelude::*;

use std::convert::TryFrom;

mod hyp_regs;
use hyp_regs::{get_hyp_reg, set_hyp_ret_reg};

mod interface;
use interface::hci::{
    hyp_error, hyp_get_manager, hyp_read, hyp_start, hyp_stop, hyp_write,hyp_get_channel_by_name
};

const MAGIC: usize = 0x1337c0d3;

#[derive(Copy, Clone)]
pub enum HcCmd {
    Start = 1,  /* start new action */
    Stop,       /* stop action */
    Read,       /* read buffer from hypervisor */
    Write,      /* write buffer TO hypervisor*/
    Error,      /* report error to hypervisor*/
    GetManager, /* returns unique chanenl ID to manager from plugin */
    GetChannelByName, /* returns existing channel mapped to unique name */
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
            6 => Ok(HcCmd::GetManager),
            7 => Ok(HcCmd::GetChannelByName),
            _ => Err(()),
        }
    }
}

#[panda::guest_hypercall]
fn hypercall_handler(cpu: &mut CPUState) -> bool {
    let magicval = get_hyp_reg(cpu, 0);
    if magicval == MAGIC {
        let action = get_hyp_reg(cpu, 1);
        // dbg!(action);
        let chan_id = get_hyp_reg(cpu, 2) as u32;
        let arg1 = get_hyp_reg(cpu, 3);
        let arg2 = get_hyp_reg(cpu, 4);

        let retval = match HcCmd::try_from(action) {
            Ok(HcCmd::Start) => hyp_start(cpu, chan_id, arg1, arg2),
            Ok(HcCmd::Write) => hyp_write(cpu, chan_id, arg1, arg2),
            Ok(HcCmd::Read) => hyp_read(cpu, chan_id, arg1, arg2),
            Ok(HcCmd::Stop) => hyp_stop(cpu, chan_id, arg1, arg2),
            Ok(HcCmd::Error) => hyp_error(cpu, chan_id, arg1, arg2),
            Ok(HcCmd::GetManager) => hyp_get_manager(cpu, chan_id, arg1, arg2),
            Ok(HcCmd::GetChannelByName) => hyp_get_channel_by_name(cpu, chan_id, arg1, arg2),
            _ => None,
        };

        if let Some(retval) = retval {
            set_hyp_ret_reg(cpu, retval);
        }
        println!("end of hc");
        true
    } else {
        false
    }
}

#[panda::init]
fn init(_: &mut PluginHandle) -> bool {
    interface::daemon_manager::init();
    true
}

#[panda::uninit]
fn exit(_: &mut PluginHandle) {
    println!("Exiting");
}
