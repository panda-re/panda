use std::sync::atomic::Ordering;

use panda::mem::{virt_to_phys, virtual_memory_read};
use panda::prelude::*;

use once_cell::sync::OnceCell;
use regex::bytes::Regex;

use crate::symbol_table;

static KASLR_OFFSET: OnceCell<target_ptr_t> = OnceCell::new();

pub fn kaslr_offset(cpu: &mut CPUState) -> target_ptr_t {
    *KASLR_OFFSET.get_or_init(|| determine_kaslr_offset(cpu))
}

const PAGE_SIZE: target_ulong = 0x1000;
const MAX_OVERLOOK_LEN: usize = 16;

fn determine_kaslr_offset(cpu: &mut CPUState) -> target_ptr_t {
    if !panda::in_kernel_mode(cpu) {
        eprintln!("WARNING: Determining kaslr offset from user mode");
    }

    if !crate::READY_FOR_KASLR_SEARCH.load(Ordering::SeqCst) {
        eprintln!("WARNING: attempting to determine KASLR offset too early");
    }

    let symbol_table = symbol_table();

    //let kaslr_search_time = Instant::now();

    let init_task_address = symbol_table.symbol_from_name("init_task").unwrap().address;
    let task_struct = symbol_table.type_from_name("task_struct").unwrap();
    let task_comm_offset = task_struct.fields["comm"].offset;
    let unshifted_comm_address =
        init_task_address as target_ulong + task_comm_offset as target_ulong;

    let bytes_in_t_ulong = std::mem::size_of::<target_ulong>();
    // 0x80000000 -> 0xffffffff (but 32 and 64 bit)
    //let (start, end) = (1 << (8 * (bytes_in_t_ulong) - 1), target_ulong::MAX);

    let (start, end) = if bytes_in_t_ulong == 4 {
        (0x8000_0000 as target_ulong, 0xffff_ffff as target_ulong)
    } else {
        (
            0xffff_8000_0000_0000_u64 as target_ulong,
            0xffff_ffff_ffff_ffff_u64 as target_ulong,
        )
    };

    // TODO: add constants for more architectures
    #[cfg(feature = "x86_64")]
    {
        const PUD_SHIFT: u64 = 30;
        const PUD_SIZE: u64 = 1 << PUD_SHIFT;
        const PUD_MASK: u64 = PUD_SIZE - 1;

        const SWAPPER_SEARCH_1: &[u8] = b"swapper\x00\x00\x00\x00\x00\x00\x00\x00";
        const SWAPPER_SEARCH_2: &[u8] = b"swapper/0\x00\x00\x00\x00\x00\x00";

        const SWAPPER_SEARCH_LEN: usize = 15;

        let offset_from_pud = unshifted_comm_address & PUD_MASK;

        for ptr in (start..=end).step_by(PUD_SIZE as usize) {
            if virt_to_phys(cpu, ptr).is_some() {
                if let Ok(res) = virtual_memory_read(cpu, ptr + offset_from_pud, SWAPPER_SEARCH_LEN)
                {
                    if res == SWAPPER_SEARCH_1 || res == SWAPPER_SEARCH_2 {
                        let offset_found = ptr + offset_from_pud;
                        let kaslr_offset = offset_found - unshifted_comm_address;

                        return kaslr_offset;
                    }
                }
            }
        }
    }

    // 0xffff8000000
    // 0x80..00
    // 0xff..ff

    let mut ptr = start;

    // TODO: Regex is probably overkill for this, probably worth just switching to
    // a standard substring search
    let swapper_searcher: regex::bytes::Regex =
        Regex::new(r"swapper(/0|\x00\x00)\x00\x00\x00\x00\x00\x00").unwrap();

    /*
     * In addition to checking each contiguous page we need to check overlaps
     * in pages. We save the length of the SWAPPER_SIGNATURE (less 1) and if
     * the previous page was valid we add it to our result when checking.
     */

    let mut tmp_overflow = [0u8; MAX_OVERLOOK_LEN - 1];
    let mut tmp_overflow_addr = None;

    while ptr < end - PAGE_SIZE - 1 {
        if virt_to_phys(cpu, ptr).is_some() {
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
                    let kaslr_offset = offset_found - unshifted_comm_address;

                    //dbg!(kaslr_search_time.elapsed());
                    //eprintln!("kaslr_offset = {:#x?}", kaslr_offset);
                    //eprintln!("offset_found = {:#x?}", offset_found);
                    //eprintln!("unshifted_comm_address = {:#x?}", unshifted_comm_address);

                    return kaslr_offset;
                }
            }
        }

        ptr += PAGE_SIZE;
    }

    panic!("cosi failed kaslr offset search")
}
