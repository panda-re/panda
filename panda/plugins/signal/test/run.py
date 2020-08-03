import wget
import subprocess
from pathlib import Path

from panda import blocking, Panda
from panda.extras.proc_write_capture import ProcWriteCapture

BIN_NAME = "sig_logger"
PROG_DIR = BIN_NAME
HOST_PROG_DIR = Path(__file__).parent.absolute().joinpath(PROG_DIR)
HOST_PROG_PATH = HOST_PROG_DIR.joinpath(BIN_NAME)

def host_build_test_progs():
    output = subprocess.check_output(
        ["make", "clean", "&&", "make"],
        shell=True,
        cwd=str(HOST_PROG_DIR)
    )
    print(output.decode("utf-8"))
    assert(HOST_PROG_PATH.is_file())

@blocking
def run_in_guest():

    pwc = ProcWriteCapture(panda, f"{BIN_NAME}", log_dir = "./pwc_log")

    panda.revert_sync("root")
    panda.copy_to_guest(str(HOST_PROG_DIR))

    run_cmds = [

        # Start the test program, give it a sec to register handlers
        f"cd ./{PROG_DIR}",
        f"./{BIN_NAME} &",
        f"sleep 1",

        # SIGINT
        f"kill -s 2 $(ps aux | grep \'[{str(BIN_NAME)[0]}]{str(BIN_NAME)[1:]}\' | awk \'{{print $2}}\')",

        # SIGSEGV
        f"kill -s 11 $(ps aux | grep \'[{str(BIN_NAME)[0]}]{str(BIN_NAME)[1:]}\' | awk \'{{print $2}}\')",

        # SIGIABRT
        f"kill -s 6 $(ps aux | grep \'[{str(BIN_NAME)[0]}]{str(BIN_NAME)[1:]}\' | awk \'{{print $2}}\')",
    ]

    for cmd in run_cmds:
        print(panda.run_serial_cmd(cmd, no_timeout=True))

    print("Captured logs:")
    for fw in pwc.get_files_written():
        print(fw)

if __name__ == "__main__":

    host_build_test_progs()

    panda = Panda(
        generic = "x86_64_ubuntu_1804",
        #arch = "x86_64",
        extra_args = "-nographic",
        expect_prompt = rb"root@ubuntu:.*",
        mem = "1G"
    )

    panda.queue_async(run_in_guest)
    panda.run()