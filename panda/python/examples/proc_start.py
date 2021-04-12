'''
proc_start.py

Makes use of the proc_start_linux plugin to get output.

Run with: python3 proc_start.py
'''

from pandare import Panda
from rich import print
from sys import argv

arch = argv[1] if len(argv) > 1 else "arm"
panda = Panda(generic=arch)

@panda.queue_blocking
def do_stuff():
    panda.revert_sync("root")
    for command in ["ls -la", "whoami", "sleep 1", "uname -r"]:
        print(panda.run_serial_cmd("LD_SHOW_AUXV=1 "+command))
    panda.end_analysis()

@panda.ppp("proc_start_linux","on_rec_auxv")
def rec_auxv(cpu, tb, av):
    print("[bold magenta][START PyPANDA on_recv_auxv][/bold magenta]")
    print("[bold red]Arguments: [/bold red]",end="")
    for i in range(av.argc):
        print(f'[bold red]{panda.ffi.string(av.argv[i])},[/bold red]',end="")
    print()
    print("[bold green]Environment: [/bold green]",end="")
    for i in range(av.envc):
        print(f'"[bold green]{panda.ffi.string(av.envp[i])}[/bold green]",',end="")
    print()
    print(f"[bold blue]AT_SYSINFO_EHDR: 0x{av.ehdr:x}[/bold blue]")
    print(f"[bold blue]AT_HWCAP:        {av.hwcap:x}[/bold blue]")
    print(f"[bold blue]AT_PAGESZ:       {av.pagesz}[/bold blue]")
    print(f"[bold blue]AT_CLKTCK:       {av.clktck}[/bold blue]")
    print(f"[bold blue]AT_PHDR:         0x{av.phdr:x}[/bold blue]")
    print(f"[bold blue]AT_PHENT:        {av.phent}[/bold blue]")
    print(f"[bold blue]AT_PHNUM:        {av.phnum}[/bold blue]")
    print(f"[bold blue]AT_BASE:         0x{av.base:x}[/bold blue]")
    print(f"[bold blue]AT_FLAGS:        0x{av.flags:x}[/bold blue]")
    print(f"[bold blue]AT_ENTRY:        0x{av.entry:x}[/bold blue]")
    print(f"[bold blue]AT_UID:          {av.uid}[/bold blue]")
    print(f"[bold blue]AT_EUID:         {av.euid}[/bold blue]")
    print(f"[bold blue]AT_GID:          {av.gid}[/bold blue]")
    print(f"[bold blue]AT_EGID:         {av.egid}[/bold blue]")
    print(f"[bold blue]AT_SECURE:       {av.secure}[/bold blue]")
    print(f"[bold blue]AT_RANDOM:       0x{av.random:x}[/bold blue]")
    print(f"[bold blue]AT_HWCAP2:       0x{av.hwcap2:x}[/bold blue]")
    print(f"[bold blue]AT_EXECFN:       {panda.ffi.string(av.execfn)}[/bold blue]")
    print(f"[bold blue]AT_PLATFORM:     {av.platform}[/bold blue]")
    print("[bold magenta][END PyPANDA on_rec_auxv][/bold magenta]")

    @panda.hook(av.entry)
    def hook(cpu,tb, h):
        try:
            print(panda.virtual_memory_read(cpu,av.program_header,4))
            print('this should read "\\x7f7FELF" (though sometimes it wont if its not in memory)')
        except Exception as e:
            print(f"whoops. failed to read. probably not paged in yet. {str(e)}")
        h.enabled = False
    

panda.run()
