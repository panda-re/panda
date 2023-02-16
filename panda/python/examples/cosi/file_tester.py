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
            mnt_dentry = mnt_pt.mnt_mountpoint
            mname = dname
            while mnt_dentry._ptr != mnt_dentry.d_parent._ptr:
                mname = mnt_dentry.d_name.name.null_terminated() + '/' + mname
                mnt_dentry = mnt_dentry.d_parent
            cosi_fd.append(mname)
            idx += 1

        comm = cosi_cur.comm

        print(f"Current task: {comm}")
        print(f"\t{cosi_fd=} | {open_fds=:b} | {ofd_arr}")

        return 1


    # run a command
    panda.run_serial_cmd("cat /proc/version")

    # print info about the current process
    print_current_process_files(panda)

    panda.end_analysis()

panda.run()
