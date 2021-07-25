from pandare import Panda
from rich import print, inspect
from sys import argv
arch = argv[1]
panda = Panda(generic=arch)


'''
the arm generic image does not have "curl"
we could install it OR we could show that it doesn't 
matter which program we use
'''
if arch == "arm":
    program_name = "wget"
    # I tried and couldn't get it to work with https. but it works on 
    # other architectures.
    command_str = "wget --no-check-certificate  http://www.ll.mit.edu/sites/default/files/styles/ifde_wysiwyg__floated/public/other/image/2018-04/New_Full_Logo-BLACK-2500-lissajou-only-square.png -O o.png"
else:
    program_name = "curl"
    command_str = "curl -k https://www.ll.mit.edu/sites/default/files/styles/ifde_wysiwyg__floated/public/other/image/2018-04/New_Full_Logo-BLACK-2500-lissajou-only-square.png --output o.png"


#%%
from os.path import exists

recording_name = "curlfile"+arch

if not exists(f"{recording_name}-rr-snp"):
    print("recordig did not exist")
    @panda.queue_blocking
    def do_stuff():
        panda.revert_sync("root")
        panda.run_monitor_cmd(f"begin_record {recording_name}")
        print(panda.run_serial_cmd(command_str))
        print(panda.run_serial_cmd("ls -la"))
        panda.run_monitor_cmd("end_record")
        panda.stop_run()
    panda.run()
else:
    print("recording exists. not remaking recording")


def try_read_str(cpu, arg_val):
    try:
        return panda.read_str(cpu, arg_val).encode("utf8",errors="ignore")
    except:
        return b"?"

@panda.ppp("syscalls2", "on_all_sys_enter")
def sys_enter(*args):
    print("enter")

@panda.ppp("syscalls2", "on_all_sys_return")
def sys_exit(*args):
    print("exit")

recovered_buf = b""
'''
So this is going to capture the fwrite from wget or curl.
If we really cared we would capture fopen and fptr and make sure
we only get reads from that FILE*. As of yet it hasn't been an issue.
This recovers the data just fine.
'''
@panda.hook_symbol("libc", "fwrite")
def hook_fwrite(cpu, tb, h):
    global recovered_buf, program_name
    if program_name not in panda.get_process_name(cpu):
        h.enabled = False
        return
    ptr, size, count, fptr = [panda.arch.get_arg(cpu,i) for i in range(4)]
    try:
        total_size = size*count
        buf = panda.virtual_memory_read(cpu, ptr, total_size)
        print(f"hook_fwrite {buf[:100]}")
        recovered_buf += buf
    except:
        print("couldn't read fwrite")

# We use these global hook types as a way to track the previous
# hook information passed
prevcall = ""
prevtype = "0x%x"

'''
This is the return from our functions. It gets the type and based on the
globals prints out the information
'''
def generic_hook_return(cpu, tb, h):
    procname = panda.get_process_name(cpu)
    global prevcall, prevtype
    result = panda.arch.get_arg(cpu, 0)
    space1 = (30-len(procname))*' '
    space2 = (50-len(prevcall))*' '
    if prevtype == "char*": 
        result_str = try_read_str(cpu, result)
    else:
        result_str = prevtype % result
    print(f"[bold magenta]{procname}[/bold magenta]{space1}{prevcall}{space2}= {result_str}")
    h.enabled = False

'''
This is our generic hook_symbol function. It sets up a new hook for each of
our labeled hooks and makes another hook for our return hook.
'''
def hook_symbol(symbol):
    @panda.hook_symbol(symbol[0],symbol[1])
    def do_generic_hook(cpu, tb, h):
        global program_name, prevcall, prevtype
        if program_name not in panda.get_process_name(cpu):
            h.enabled = False
            return
        args = symbol[2]
        prevcall = f"[bold yellow]{symbol[1]}[/bold yellow]("
        for i in range(len(args)):
            if i > 0:
                prevcall += ","
            arg_val = panda.arch.get_arg(cpu, i)
            if args[i] == "char*":
                arg_string = try_read_str(cpu, arg_val)
                prevcall += f'{arg_string}'
            elif args[i] == "ptr":
                prevcall += f"0x{arg_val:x}"
            elif args[i] == "int":
                prevcall += f"{arg_val:d}"
        prevcall += ")"
        prevtype = symbol[3]
        ra = panda.arch.get_return_address(cpu)
        if ra != 0:
            panda.hook(ra,enabled=True,kernel=False,asid=panda.current_asid(cpu))(generic_hook_return)



# these are various functions we are interested in looking at
hooked_symbols = [("libc", "fopen", ["char*", "char*"], "0x%x"),
                ("libc", "strlen", ["char*"], "%d"),
                ("libc", "strdup", ["char*"], "char*"),
                ("libc", "pipe", ["ptr"], "%d"),
                ("libc", "close", ["int"], "%d"),
                ("libc", "signal", ["int", "ptr"], "%d"),
                ("libc", "getenv", ["char*"], "char*"),
                ("libc", "fwrite", ["ptr", "int", "int", "ptr"], "%d"),
                #("libc", "malloc", ["ptr"], "0x%x"), # lots of output
                ("curl","curl_strequal", ["char*", "char*"], "%d"),
                ("curl","curl_strnequal", ["char*", "char*"], "%d"),
                ("curl", "curl_version_info", ["int"], "0x%x")
                ]
#loop over each
for symbol in hooked_symbols:
    hook_symbol(symbol)

panda.run_replay(recording_name)

# write out recovered png file
with open("o.png","wb") as f:
    f.write(recovered_buf)
