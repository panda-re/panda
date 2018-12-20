import binaryninja as bn

from binaryninja import (
    PluginCommand, BackgroundTaskThread,
    HighlightStandardColor
)

def do_highlight(bv, base_addr=None):
    f = open("/Users/raywang/dev/panda-stuff/cov_files/slice_addrs", "r").readlines()
    f = [line.strip() for line in f]
    addrs = [(int(line.split(":")[0], 16), line.split(":")[1]) for line in f]

    if base_addr:
        addrs = [(addr - base_addr, hits) for addr, hits in addrs if addr > base_addr]
    print sorted(map(hex, [pair[0] for pair in addrs]))

    for func in bv.functions:
        # first, clear highlights
        funcaddrs = [i[1] for i in func.instructions]
        [func.set_user_instr_highlight(addr, HighlightStandardColor.NoHighlightColor) for addr in funcaddrs]
        # Now highlight
        [func.set_user_instr_highlight(addr, HighlightStandardColor.YellowHighlightColor) for addr, hits in addrs]
        [func.set_comment_at(addr, hits + " times") for addr, hits in addrs]


def do_coverage(bv, module, pie = False):
    f = open("/Users/raywang/dev/panda-stuff/cov_files/coverage", "r").readlines()
    addrs = set([int(ln.strip().split(":")[1], 16) for ln in f if module in ln and not ln.startswith("base:")])
    
    if pie:
        base = [ln.strip().split(":")[2] for ln in f if ln.startswith("base:") and module in ln][0]
        base = int(base, 16)
        print "base", hex(base)
        
        addrs = [addr - base for addr in addrs]

    print "addrs", sorted(map(hex, addrs))

    for bb in bv.basic_blocks:
            bb.set_user_highlight(HighlightStandardColor.NoHighlightColor)

    for addr in addrs:
        try:
            bb = bv.get_basic_blocks_at(addr)[0]
            bb.set_user_highlight(HighlightStandardColor.CyanHighlightColor)
        except:
            pass


def clear(bv):
    for func in bv.functions:
        # first, clear highlights
        funcaddrs = [i[1] for i in func.instructions]
        [func.set_user_instr_highlight(addr, HighlightStandardColor.NoHighlightColor) for addr in funcaddrs]
    
    for bb in bv.basic_blocks:
        bb.set_user_highlight(HighlightStandardColor.NoHighlightColor)
