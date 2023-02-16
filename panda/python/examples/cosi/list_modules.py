from pandare import Panda

panda = Panda(generic="x86_64")

class Module:
    def __init__(self, module):
        self.inner = module

    def name(self) -> str:
        try:
            return self.inner.kobj.name.null_terminated()
        except:
            return "[???]"

    def args(self) -> str:
        try:
            return self.inner.mod.args.null_terminated()
        except:
            return ""

    def ref_count(self) -> int:
        return self.inner.kobj.kref.refcount.refs.counter

    def __repr__(self):
        return f'<KernelModule {self.name()}>'

def get_modules(panda):
    module_set = panda.cosi.get('kset', 'module_kset')

    # the module set's `list` field is a linked list of kobjects whose siblings are 
    # linked together via the `entry` field
    raw_modules = module_set.list.as_linux_list('entry', list_entry_type="kobject")

    # the actual module info is stored in the container struct (`module_kobject`) where
    # the inner kobject is the `kobj` field
    modules = [
        Module(module.container_of('module_kobject', 'kobj')) for module in raw_modules
    ]

    return modules

@panda.queue_blocking
def run_cmd():
    panda.revert_sync("root")

    # set the volatility symbol table for cosi to use
    panda.load_plugin("cosi", { "profile": "ubuntu:4.15.0-72-generic:64.json.xz" })

    # run a command
    panda.run_serial_cmd("cat /proc/version")

    # print the loaded kernel modules
    print("Modules:")
    for module in get_modules(panda):
        if module.ref_count() != 0:
            print(f" - {module.name()} (refs={module.ref_count()})")

    panda.end_analysis()

panda.run()
