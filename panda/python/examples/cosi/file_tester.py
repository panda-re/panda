from pandare import Panda

panda = Panda(generic="x86_64")
panda.load_plugin("osi")
panda.load_plugin("osi_linux")


@panda.queue_blocking
def run_cmd():
    panda.revert_sync("root")

    # set the volatility symbol table for cosi to use
    panda.load_plugin("osi2", { "profile": "ubuntu:4.15.0-72-generic:64.json.xz" })

    @panda.cb_asid_changed()
    def print_current_process_files(cpu, old, new):
        # get the address of current_task
        current_task_addr = panda.cosi.find_per_cpu_address('current_task')

        # get the type of current_task
        task_struct = panda.cosi.type_from_name('task_struct')

        files_offset = task_struct['files'].offset
        files_type_size = 8
        files_ptr = current_task_addr + files_offset
        #files = panda.virtual_memory_read(panda.get_cpu(), files_ptr, files_size, fmt='bytes')

        files_struct = panda.cosi.type_from_name('files_struct')
        fd_array_offset = files_struct['fd_array'].offset
        #print(dir(files_struct['fd_array']))
        fd_array_type = panda.cosi.base_type_from_name(files_struct['fd_array'].type_name)
        fd_array_type_size = 64*8
        fd_array_ptr = files_ptr + fd_array_offset
        # read fd_array field of file_struct, has type *file/is an array of file pointers
        fd_array = panda.virtual_memory_read(cpu, fd_array_ptr, fd_array_type_size, fmt = 'ptrlist')

        # get offset of fdtab inside of files_struct
        fdtab_offset = files_struct['fdtab'].offset
        fdtable = panda.cosi.type_from_name('fdtable')

        # get offset of the fd: **file field in fdtable to try and resolve that
        # ideally this should give us the same information as fd_array above, eventually
        fd_offset = fdtable['fd'].offset
        fd_type_size = 8
        # fd_ptr_ptr has type **file
        fd_ptr_ptr = files_ptr + fdtab_offset + fd_offset
        # maybe has type *file?
        fd_ptr = panda.virtual_memory_read(cpu, fd_ptr_ptr, fd_type_size, fmt='int')

        open_fds_offset = fdtable['open_fds'].offset
        open_fds_type_size = 8
        open_fds_ptr = files_ptr + fdtab_offset + open_fds_offset
        open_fds = panda.virtual_memory_read(cpu, open_fds_ptr, open_fds_type_size, fmt='int')

        fd_list = []
        bv=open_fds
        for i in range(0, 64):
            if bv%2:
                fd_list.append(i)
            bv = bv>>1

        for e in range(len(fd_array)):
            if e in fd_list:
                if fd_array[e] != 0:
                    print(f"Got one! idx {e} in {fd_array[e]=:x}")
                else:
                    print(f"False positive on idx {e}")
            elif fd_array[e]!= 0:
                print(f"False negative, {fd_array[e]=:x}")
        
        # read the comm field to get the process name/command
        comm_ptr = current_task_addr + task_struct['comm'].offset
        comm = panda.read_str(cpu, comm_ptr)

        print(f"Current task: {comm}")
        print(f"\t{fd_ptr_ptr:x} | {fd_ptr=:x} | {fd_array} | {open_fds=:x} | {fd_list=}")

        current = panda.plugins['osi'].get_current_process(cpu)
        if current.name != panda.ffi.NULL:
            name = panda.ffi.string(current.name).decode('utf-8', errors='ignore')
        else:
            name = "ERROR"
        print(f"OSI name: {name}")
        MAX_FD_LIM = 64
        for i in range(0, MAX_FD_LIM):
            try:
                fname = panda.plugins["osi_linux"].osi_linux_fd_to_filename(cpu, current, i)
            except:
                continue
            if fname:
                if res_name := panda.ffi.string(fname).decode('utf-8', errors='ignore'):
                    if res_name != panda.ffi.NULL:
                        print(f"{i=} | {res_name=}")


    # run a command
    panda.run_serial_cmd("cat /proc/version")

    # print info about the current process
    #print_current_process_files(panda)

    panda.end_analysis()

panda.run()