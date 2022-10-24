from pandare import Panda
from termcolor import colored
import os

# Please don't do it this way normally
code = """#include <stdio.h>
#include <unistd.h>

int main() {
    printf("Hello World!\\n");
    sleep(3);

    return 0;
}
"""
os.system(f'printf {repr(code)} | gcc -x c - -o hello_world_x86_64')

panda = Panda(generic="x86_64")
panda.load_plugin("linjector", {
    "require_root": False,
    "guest_binary": "hello_world_x86_64",
    "proc_name": "cat"
})

@panda.queue_blocking
def run_cmd():
    panda.revert_sync("root")
    print(colored(panda.run_serial_cmd("cat /proc/cpuinfo"), "white", attrs=['bold']))
    panda.end_analysis()

panda.run()
