from pandare import Panda

panda = Panda(generic="x86_64")
panda.load_plugin("osi")
panda.load_plugin("osi_linux")


@panda.queue_blocking
def run_cmd():
    panda.revert_sync("root")

    # set the volatility symbol table for cosi to use
    panda.load_plugin("cosi", { "profile": "ubuntu:4.15.0-72-generic:64.json.xz" })

    @panda.cb_asid_changed()
    def print_current_process_files(cpu, old, new):
        cosi_cur = panda.cosi.get('task_struct', 'current_task', per_cpu=True)
        try:
            cosi_fdt = cosi_cur.files.fdt
        except Exception as e:
            print(f"Goofed: {e}")
            return 0
        max_fds = cosi_fdt.max_fds
        open_fds = cosi_fdt.open_fds.deref()
        ofd_arr = []
        bv = open_fds

        for i in range(len(f"{open_fds:b}")):
            if bv%2:
                ofd_arr.append(i)
            bv>>1
        cosi_fd = []
        print(cosi_fdt.fd)
        idx = 0
        fd_ptr = cosi_fdt.fd._ptr
        for fd in cosi_fdt.fd[:max_fds]:
            if fd._ptr == 0:
                break
            '''
            try:
                fd_read = panda.virtual_memory_read(cpu, fd_ptr, length = 8, fmt='int')
                print(f"[python] Read {fd_read:x} from {fd_ptr:x}")
            except Exception as e:
                print(f"[python err] Couldn't read {fd_ptr:x} | {e}")
                
            fd_ptr += 8
            '''
            #print(f"[python] FD {idx} ptr: {fd._ptr=:x} | {fd.f_path.dentry._ptr:x}")
            dname = ""
            dentry = fd.f_path.dentry
            while dentry._ptr != dentry.d_parent._ptr:
                if dname == "":
                    term = ''
                else:
                    term = '/'
                dname = dentry.d_name.name.null_terminated() + term + dname
                dentry = dentry.d_parent
            mnt_root = ""
            mnt_pt = fd.f_path.mnt.container_of('mount', 'mnt')
            #print(f"Mount struct ptr: {mnt_pt._ptr:x}")
            mnt_dentry = mnt_pt.mnt_mountpoint
            #print(f"{mnt_dentry.d_name.name.null_terminated()=}")
            mname = dname
            while mnt_dentry._ptr != mnt_dentry.d_parent._ptr:
                #print(f"mnt_dentry ptr: {mnt_dentry._ptr:x}")
                #print(f"Component: {mnt_dentry.d_name.name.null_terminated()}")
                mname = mnt_dentry.d_name.name.null_terminated() + '/' + mname
                mnt_dentry = mnt_dentry.d_parent
            cosi_fd.append(mname)
            #cosi_fd.append(dname)
            idx += 1

        comm = cosi_cur.comm

        print(f"Current task: {comm}")
        print(f"\t{cosi_fd=} | {open_fds=:b} | {ofd_arr}")
        '''
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
        '''
        return 1


    # run a command
    panda.run_serial_cmd("cat /proc/version")

    # print info about the current process
    #print_current_process_files(panda)

    panda.end_analysis()

panda.run()
