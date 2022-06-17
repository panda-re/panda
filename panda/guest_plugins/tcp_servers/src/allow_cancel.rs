use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

pub struct AllowCancel<T>(T, Arc<AtomicBool>);

#[derive(Clone)]
pub struct CancelSignal(Arc<AtomicBool>);

impl CancelSignal {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst)
    }
}

impl Clone for AllowCancel<panda_channels::Channel> {
    fn clone(&self) -> Self {
        Self(self.0.clone(), Arc::clone(&self.1))
    }
}

impl<T> AllowCancel<T> {
    pub fn new(io: T) -> Self {
        Self(io, Arc::new(AtomicBool::new(false)))
    }

    pub fn cancel_signal(&self) -> CancelSignal {
        CancelSignal(Arc::clone(&self.1))
    }

    pub fn with_signal(self, cancel_signal: CancelSignal) -> Self {
        Self(self.0, cancel_signal.0)
    }
}

macro_rules! dbg {
    ($expr:expr) => {
        //panda_channels::Channel::main(&format!(
        //    "[{}:{}] {} = {:?}",
        //    file!(),
        //    line!(),
        //    stringify!($expr),
        //    $expr,
        //))
    };
}

impl<T: Write> Write for AllowCancel<T> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if !self.1.load(Ordering::SeqCst) {
            dbg!(buf.len());

            self.0.write(buf)
        } else {
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Connection ended",
            ))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.1.load(Ordering::SeqCst) {
            dbg!("flushing");

            self.0.flush()
        } else {
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Connection ended",
            ))
        }
    }
}

impl<T: Read> Read for AllowCancel<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.1.load(Ordering::SeqCst) {
            //dbg!(buf.len());

            self.0.read(buf).map(|len| {
                if len != 0 {
                    dbg!(len);
                }

                len
            })
        } else {
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Connection ended",
            ))
        }
    }
}

impl<T: Seek> Seek for AllowCancel<T> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        if !self.1.load(Ordering::SeqCst) {
            self.0.seek(pos)
        } else {
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Connection ended",
            ))
        }
    }
}
