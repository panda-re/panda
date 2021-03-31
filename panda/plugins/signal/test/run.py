import wget
import subprocess
import shutil
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
def prepare_plugins():

    # Apply signal supression by process, for the 3 signals we're about to send
    bin_name_str = f"{BIN_NAME}".encode('ascii')
    panda.plugins['signal'].block_sig_by_proc(2, bin_name_str)
    panda.plugins['signal'].block_sig_by_proc(11, bin_name_str)
    panda.plugins['signal'].block_sig_by_proc(6, bin_name_str)

@blocking
def run_in_guest():

    # Setup write capture, mirrors files create to hyper visor
    host_log_dir = "./pwc_log"
    if Path(host_log_dir).exists() and Path(host_log_dir).is_dir():
        shutil.rmtree(host_log_dir)
    pwc = ProcWriteCapture(panda, f"{BIN_NAME}", log_dir = host_log_dir)

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

        # SIGABRT
        f"kill -s 6 $(ps aux | grep \'[{str(BIN_NAME)[0]}]{str(BIN_NAME)[1:]}\' | awk \'{{print $2}}\')",
    ]

    for cmd in run_cmds:
        print(panda.run_serial_cmd(cmd, no_timeout=True))

    print("Captured logs:")
    hyper_mirrored_file_paths = pwc.get_files_written()
    for fp in hyper_mirrored_file_paths:
        print(fp)

    # Captured a single log file
    assert(len(hyper_mirrored_file_paths) == 1)
    log = Path(next(iter(hyper_mirrored_file_paths)))
    assert(log.is_file())

    # Signals successfully supressed (via swap to SIGWINCH)
    with log.open() as f:
        lines = f.readlines()
        for l in lines:

            # Negative test
            assert("SIGABRT" not in l)
            assert("SIGSEGV" not in l)
            assert("SIGINT" not in l)

            # Postive test
            assert("SIGWINCH" in l)

    print("\nTEST OK! Signals sucessfully supressed\n")
    panda.panda_finish() # TODO: does not return? Either way, PANDALOG written
    panda.end_analysis()

if __name__ == "__main__":

    host_build_test_progs()

    panda = Panda(
        generic = "x86_64_ubuntu_1804",
        extra_args = "-nographic -pandalog test_sig_suppress.plog",
        expect_prompt = rb"root@ubuntu:.*",
        mem = "1G"
    )

    panda.queue_async(prepare_plugins)
    panda.queue_async(run_in_guest)
    panda.run()