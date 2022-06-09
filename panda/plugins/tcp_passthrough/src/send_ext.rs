use panda::plugins::guest_plugin_manager::Channel;
use serde::Serialize;

pub(crate) trait SendExt {
    fn send<T: Serialize>(&mut self, val: T);
}

impl SendExt for Channel {
    fn send<T: Serialize>(&mut self, val: T) {
        self.write_packet(&bincode::serialize(&val).unwrap());
    }
}
