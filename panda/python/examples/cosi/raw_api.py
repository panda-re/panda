from pandare import Panda

panda = Panda(generic="x86_64")

def print_current_process(panda):
    # get the address of current_task
    current_task_addr = panda.cosi.find_per_cpu_address('current_task')

    # get the type of current_task
    task_struct = panda.cosi.type_from_name('task_struct')

    # get the offset and size in bytes of the pid field
    pid_offset = task_struct['pid'].offset
    pid_type = task_struct['pid'].type_name
    pid_type = panda.cosi.base_type_from_name(pid_type)
    pid_int_size = pid_type.size()

    # read the pid from the current_task
    pid_ptr = current_task_addr + pid_offset
    pid = panda.virtual_memory_read(panda.get_cpu(), pid_ptr, pid_int_size, fmt='int')

    # read the comm field to get the process name/command
    comm_ptr = current_task_addr + task_struct['comm'].offset
    comm = panda.read_str(panda.get_cpu(), comm_ptr)

    print(f"Current task: {comm} (pid={pid})")

@panda.queue_blocking
def run_cmd():
    panda.revert_sync("root")

    # set the volatility symbol table for cosi to use
    panda.load_plugin("cosi", { "profile": "ubuntu:4.15.0-72-generic:64.json.xz" })

    # run a command
    panda.run_serial_cmd("cat /proc/version")

    # print info about the current process
    print_current_process(panda)

    panda.end_analysis()

panda.run()
