use std::io::Cursor;

use panda::mem::{virt_to_phys, virtual_memory_read};
use panda::prelude::*;
use panda::sys::panda_virt_to_phys_external;
mod json_types;
use json_types::VTypeJson;

use byteorder::{BigEndian, LittleEndian, ReadBytesExt};

use once_cell::sync::OnceCell;

use regex::bytes::Regex;

static SYMBOL_TABLE: OnceCell<VTypeJson> = OnceCell::new();
static KASLR_OFFSET: OnceCell<target_ulong> = OnceCell::new();
const PAGE_SIZE: target_ulong = 0x1000;
const MAX_OVERLOOK_LEN: usize = 16;

fn determine_kaslr_offset(cpu: &mut CPUState) {
    println!("searching mem for offset");
    let symbol_table = SYMBOL_TABLE.get().unwrap();
    let init_task_address = symbol_table.symbol_from_name("init_task").unwrap().address;
    let task_struct = symbol_table.type_from_name("task_struct").unwrap();
    let task_comm_offset = task_struct.fields["comm"].offset;
    let unshifted_comm_address =
        init_task_address as target_ulong + task_comm_offset as target_ulong;

    let bytes_in_t_ulong = std::mem::size_of::<target_ulong>();
    // 0x80000000 -> 0xffffffff (but 32 and 64 bit)
    let (start, end) = (1 << (8 * (bytes_in_t_ulong) - 1), target_ulong::MAX);
    // let (start, end) = (0,target_ulong::MAX);

    println!("start: {:x} {:x}", start, end);

    let mut ptr = start;
    let swapper_searcher: regex::bytes::Regex =
        Regex::new(r"swapper(/0|\x00\x00)\x00\x00\x00\x00\x00\x00").unwrap();

    /*
     * In addition to checking each contiguous page we need to check overlaps
     * in pages. We save the length of the SWAPPER_SIGNATURE (less 1) and if
     * the previous page was valid we add it to our result when checking.
     */

    let mut tmp_overflow = [0u8; MAX_OVERLOOK_LEN - 1];
    let mut tmp_overflow_addr: Option<target_ulong> = None;

    while ptr < end - PAGE_SIZE - 1 {
        match virt_to_phys(cpu, ptr) {
            target_ulong::MAX => {}
            _ => {
                if let Ok(mut res) = virtual_memory_read(cpu, ptr, PAGE_SIZE as usize) {
                    let mut had_overflow: bool = false;

                    // do we have a valid previous page? if so add to the array
                    if let Some(overflow_addr) = tmp_overflow_addr {
                        if overflow_addr == ptr - PAGE_SIZE {
                            // save previous start before we potentially change the vector
                            had_overflow = true;
                            res.append(&mut tmp_overflow.to_vec());
                            res.rotate_right(tmp_overflow.len());
                        }
                    }

                    let (start, end) = if had_overflow {
                        (tmp_overflow.len(), tmp_overflow.len() * 2)
                    } else {
                        (0, tmp_overflow.len())
                    };
                    tmp_overflow.copy_from_slice(&res[start..end]);
                    tmp_overflow_addr = Some(ptr);

                    // use jetscii implementation. Might be more efficient search
                    if let Some(m) = swapper_searcher.find(&res) {
                        let offset_found: target_ulong = if had_overflow {
                            ptr as target_ulong + m.start() as target_ulong
                                - tmp_overflow.len() as target_ulong
                        } else {
                            ptr as target_ulong + m.start() as target_ulong
                        };
                        let kaslr_offset: target_ulong = offset_found - unshifted_comm_address;
                        KASLR_OFFSET.set(kaslr_offset).unwrap();
                        println!("found value at {:x}", offset_found);
                        println!("expected value at {:x}", unshifted_comm_address);
                        println!("determined offset is {:x}", kaslr_offset as target_long);
                        return;
                    }
                }
            }
        }
        if ptr % (PAGE_SIZE << 5) == 0 {
            println!("{:#x?}", ptr);
        }
        ptr += PAGE_SIZE;
    }
    println!("failed search");
    KASLR_OFFSET.set(0).unwrap();
}

#[panda::init]
fn init(_: &mut PluginHandle) -> bool {
    println!("initializing osi2");
    let filename = "/home/jmcleod/dev/ubuntu:4.4.0-170-generic:32.json.xz";
    SYMBOL_TABLE.set(VTypeJson::from_file(filename)).unwrap();
    true
}

#[panda::uninit]
fn exit(_: &mut PluginHandle) {
    println!("Exiting");
}

fn read_little_endian_int(cpu: &mut CPUState, address: target_ulong) -> u32 {
    let comm_data = virtual_memory_read(cpu, address, 4).unwrap();
    let mut rdr = Cursor::new(comm_data);
    rdr.read_u32::<LittleEndian>().unwrap()
}

fn current_process_name(cpu: &mut CPUState) -> String {
    // it's zero at the moment, but we do determine it
    let _kaslr_offset = match KASLR_OFFSET.get() {
        Some(val) => val,
        None => {
            determine_kaslr_offset(cpu);
            KASLR_OFFSET.get().unwrap()
        }
    };
    let symbol_table = SYMBOL_TABLE.get().unwrap();
    let cur_task = symbol_table.symbol_from_name("current_task").unwrap();
    let task_struct = symbol_table.type_from_name("task_struct").unwrap();
    let comm = task_struct.fields.get("comm").unwrap();
    let comm_offset = comm.offset as u64;
    let cpu_offset = symbol_table.symbol_from_name("__per_cpu_offset").unwrap();
    let cpu_0_offset = read_little_endian_int(cpu, cpu_offset.address as target_ulong);
    let current_task_ptr = read_little_endian_int(
        cpu,
        cur_task.address as target_ulong + cpu_0_offset as target_ulong,
    );
    let comm_data = virtual_memory_read(
        cpu,
        current_task_ptr as target_ulong + comm_offset as target_ulong,
        16,
    )
    .unwrap();
    let data_string = String::from_utf8(comm_data).unwrap();
    data_string
}

#[panda::asid_changed]
fn asid_changed(cpu: &mut CPUState, _old_asid: target_ulong, _new_asid: target_ulong) -> bool {
    println!("found process {}", current_process_name(cpu));
    false
}
