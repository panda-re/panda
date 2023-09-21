#!/usr/bin/env python3
from sys import argv
from pandare import Panda

# Single arg of arch, defaults to i386
arch = "mips" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

@panda.queue_blocking
def run_cmd():
    panda.revert_sync("root")
    print(panda.run_serial_cmd("wget google.com"))
    print(panda.run_serial_cmd("wget google.com"))
    print(panda.run_serial_cmd("wget google.com"))
    print(panda.run_serial_cmd("wget google.com"))
    print(panda.run_serial_cmd("wget google.com"))
    print(panda.run_serial_cmd("wget google.com"))
    print(panda.run_serial_cmd("wget google.com"))
    print(panda.run_serial_cmd("wget google.com"))
    print(panda.run_serial_cmd("wget google.com"))
    print(panda.run_serial_cmd("uname -a"))
    print(panda.run_serial_cmd("uname -a"))
    print(panda.run_serial_cmd("uname -a"))
    print(panda.run_serial_cmd("uname -a"))
    panda.end_analysis()

def read_int(address):
    return panda.virtual_memory_read(panda.get_cpu(), address, 4, fmt="int")

if arch == "mips" or arch == "mipsel":
    PAGE_SHIFT = 12
    PAGE_MASK =     0xfffff000
    NOT_PAGE_MASK = 0x00000fff
    PGD_SIZE = 4
    NOT_PAGE_GLOBAL_SHIFT = 0xffffffdf
    PGDIR_SHIFT = 0x16
    PFN_SHIFT = 0xb
    def pgd_valid(pgd):
        return True

    def pud_valid(pud):
        return True

    def pmd_valid(pmd):
        return True

    def pte_valid(pte):
        return (read_int(pte) & NOT_PAGE_GLOBAL_SHIFT) != 0
    
    def pgd_index(arg):
        return ((arg >> PGDIR_SHIFT) * PGD_SIZE)

    def pgd_offset(pgd, arg):
        return read_int(pgd + pgd_index(arg))

    def pud_offset(pgd, arg):
        return pgd

    def pmd_offset(pud, arg):
        return pud

    def pte_offset(pmd, address):
        return pmd + (((address & PAGE_MASK) >> 10) & 0xffc)

    def pte_pfn_fn(pte):
        return read_int(pte) >> PFN_SHIFT

    def address_from_pfn(pfn, address):
        return (pfn << PAGE_SHIFT) + (address & NOT_PAGE_MASK)
elif arch == "arm":
    # ARM DOES NOT CURRENTLY WORK!!!
    PAGE_SHIFT = 12
    PAGE_MASK =     0xfffff000
    NOT_PAGE_MASK = 0x00000fff
    PGD_SIZE = 8
    PGDIR_SHIFT = 0x15
    PFN_SHIFT = 0xc
    def pgd_valid(pgd):
        return True

    def pud_valid(pud):
        return True

    def pmd_valid(pmd):
        # return read_int(pmd) != 0 and read_int(pmd) & 2 == 0
        return True

    def pte_valid(pte):
        # return pte != 0
        return True
    
    def pgd_index(arg):
        return (arg >> PGDIR_SHIFT) * 8

    def pgd_offset(pgd, arg):
        return read_int(pgd + pgd_index(arg)) & 0xfffffffc

    def pud_offset(pgd, arg):
        return pgd

    def pmd_offset(pud, arg):
        return pud

    def pte_offset(pmd, address):
        return pmd + (((((address & PAGE_MASK) << 0xb) & 0xffffffff) >> 0x17) * 4) & 0xffffffff

    def pte_pfn_fn(pte):
        return read_int(pte) >> PFN_SHIFT

    def address_from_pfn(pfn, address):
        return (pfn << PAGE_SHIFT) + (address & NOT_PAGE_MASK)

def walk_page_table(cpu, address):
    proc_pgd = panda.plugins['osi'].get_current_process(cpu).pgd
    print(f"proc_pgd: {proc_pgd:#x}")
    pgd = pgd_offset(proc_pgd, address)
    print(f"pgd: {pgd:#x}")
    if pgd_valid(pgd):
        pud = pud_offset(pgd, address)
        print(f"pud: {pud:#x}")
        if pud_valid(pud):
            pmd = pmd_offset(pud, address)
            print(f"pmd: {pmd:#x}")
            if pmd_valid(pmd):
                pte = pte_offset(pmd, address)
                print(f"pte: {pte:#x}")
                if pte_valid(pte):
                    pfn = pte_pfn_fn(pte)
                    return address_from_pfn(pfn, address)
                else:
                    print("pte not valid")
            else:
                print(f"pmd not valid {pmd:#x}")
        else:
            print("pud not valid")

def walk_page_table_wrap(cpu, address):
    try:
        if out := walk_page_table(cpu, address):
            print(f"succeeded! {out:#x}")
            print(f"data: {panda.physical_memory_read(out, 4)}")
            # import ipdb
            # ipdb.set_trace()
        else:
            print("Still failed")
    except ValueError as e:
        raise e
        print(e)
        print("Failed to read code")
        import ipdb
        ipdb.set_trace()
        # phys = panda.virt_to_phys(cpu, hdr)
        # print(f"BUF: {hdr:#x}/PHYS:{phys:#x}")
        # walk_page_table(cpu, hdr)

@panda.ppp("syscalls2", "on_sys_write_enter")
def write(cpu, pc, fd, buf, count):
    try:
        print(f"buf: {buf:#x}/phys: {panda.virt_to_phys(cpu, buf):#x}")
        s = panda.read_str(cpu, buf, count)
        print(f"{walk_page_table(cpu, buf):#x}")
    except ValueError:
        hdr = buf
        print("Failed to read code")
        phys = panda.virt_to_phys(cpu, hdr)
        print(f"BUF: {hdr:#x}/PHYS:{phys:#x}")
        walk_page_table(cpu, hdr)
        s = "error"


panda.run()
