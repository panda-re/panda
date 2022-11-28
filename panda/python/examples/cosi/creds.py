from pandare import Panda

panda = Panda(generic="x86_64")

class Cred:
    def __init__(self, cred):
        self.inner = cred

    @property
    def uid(self):
        return self.inner.user.uid.val

    @property
    def gid(self):
        return self.inner.gid.val

    @property
    def egid(self):
        return self.inner.egid.val

    @property
    def euid(self):
        return self.inner.euid.val

@panda.queue_blocking
def run_cmd():
    panda.revert_sync("root")

    # set the volatility symbol table for cosi to use
    panda.load_plugin("osi2", { "profile": "ubuntu:4.15.0-72-generic:64.json.xz" })

    # run a command
    panda.run_serial_cmd("cat /proc/version")

    current_task = panda.cosi.get('task_struct', 'current_task', per_cpu=True)
    creds = Cred(current_task.cred)

    print(f"comm = {current_task.comm}")
    print(f"uid = {creds.uid}")
    print(f"gid = {creds.gid}")
    print(f"euid = {creds.euid}")
    print(f"egid = {creds.egid}")
    print()

    panda.end_analysis()

panda.run()
