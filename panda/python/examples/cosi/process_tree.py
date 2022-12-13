from pandare import Panda

panda = Panda(generic="x86_64")

def print_process_tree(panda, current=None, depth=0):
    # if the current node in the process tree is not provided, start with the root-level
    # process (init)
    if current is None:
        current = panda.cosi.get('task_struct', 'init_task')

    # print out the current process name and pid
    print(('  ' * depth) + f'L {current.comm} (pid={current.pid})')

    # read the linked list of child processes, where the list is linked via the
    # `sibling` field of the task_struct type
    children = current.children.as_linux_list('sibling')

    # iterate over the children and recursively print the process tree
    for child in children:
        print_process_tree(panda, current=child, depth=depth + 1)

@panda.queue_blocking
def run_cmd():
    panda.revert_sync("root")

    # set the volatility symbol table for cosi to use
    panda.load_plugin("cosi", { "profile": "ubuntu:4.15.0-72-generic:64.json.xz" })

    # run a command
    panda.run_serial_cmd("cat /proc/version")

    # print the process tree
    print_process_tree(panda)

    panda.end_analysis()

panda.run()
