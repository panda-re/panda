use crate::symbol_table;
use panda::plugins::cosi::{find_per_cpu_address, OsiType};
use panda::prelude::*;
#[cfg(any(feature = "mips", feature = "mipsel", feature = "arm"))]
use panda::mem::read_guest_type;
use panda::GuestType;
use std::mem::size_of;

/// Max length of process command (`comm` field in task_struct)
pub const TASK_COMM_LEN: usize = 16;


// For MIPS, we use hw_proc_id to get the current task struct
#[cfg(any(feature = "mips", feature = "mipsel"))]
panda::plugin_import!{
    static HWPROCID: Hwprocid = extern "hw_proc_id" {
        fn get_id(cpu: *mut CPUState) -> target_ulong;
    };
}

//#################################################################
//#################### Task related structures ####################
//#################################################################

#[repr(C)]
#[derive(OsiType, Debug, Clone)]
#[osi(type_name = "list_head")]
pub struct ListHead {
    pub next: target_ptr_t,
    pub prev: target_ptr_t,
}

impl ListHead {
    pub fn get_owning_struct_ptr(&self, ty: &str, field: &str, next: bool) -> Option<target_ptr_t> {
        let owning_sym = symbol_table().type_from_name(ty)?;
        let off = owning_sym.fields[field].offset as target_ptr_t;
        if next {
            Some(self.next - off)
        } else {
            Some(self.prev - off)
        }
    }
}

#[derive(Debug)]
pub struct Version {
    pub a: target_ptr_t,
    pub b: target_ptr_t,
    pub c: target_ptr_t,
}

// Digging around in kernel source for 3.7 traced these fields' types, kuid_t and kgid_t,
// through a few definitions and found they were both structs which hold a single value of type
// git_t or uid_t which are, in that kernel version, just unsigned ints
#[derive(OsiType, Debug)]
#[osi(type_name = "cred")]
pub struct CredStruct {
    pub uid: target_ptr_t,  // type unsigned int
    pub gid: target_ptr_t,  // type unsigned int
    pub euid: target_ptr_t, // type unsigned int
    pub egid: target_ptr_t, // type unsigned int
}

#[repr(C)]
#[derive(OsiType, Debug, Clone)]
#[osi(type_name = "mm_struct")]
pub struct MmStruct {
    pub pgd: u32,                  // type *unnamed_bunch_of_stuff_3
    pub arg_start: target_ptr_t,   // type long unsigned int
    pub start_brk: target_ptr_t,   // type long unsigned int
    pub brk: target_ptr_t,         // type long unsigned int
    pub start_stack: target_ptr_t, // type long unsigned int
    pub mmap: target_ptr_t,        // type *vm_area_struct
}

#[repr(C)]
#[derive(OsiType, Debug, Clone)]
#[osi(type_name = "task_struct")]
pub struct TaskStruct {
    // Only one of tasks or next_task will exist as a field
    #[osi(osi_type)]
    pub tasks: ListHead, // type list_head
    //next_task: target_ptr_t, // type ??
    pub pid: u32,                   // type int
    pub tgid: u32,                  //type int
    pub group_leader: target_ptr_t, // type *task_struct
    pub thread_group: target_ptr_t, // type list_head

    // Only one of real_parent or p_opptr will exist as a field
    pub real_parent: target_ptr_t, // type *task_struct
    //p_opptr: target_ptr_t, // type ??

    // Only one of parent or p_pptr will exist as a field
    pub parent: target_ptr_t, // type *task_struct
    //p_pptr: target_ptr_t, // type ??
    pub mm: target_ptr_t,          // type *mm_struct
    pub stack: target_ptr_t,       // type *void
    pub real_cred: target_ptr_t,   // type *cred
    pub cred: target_ptr_t,        // type *cred
    pub comm: [u8; TASK_COMM_LEN], // type char[]
    pub files: target_ptr_t,       // type *files_struct
    pub start_time: target_ptr_t,  // type long long unsigned int
    #[osi(osi_type)]
    pub children: ListHead, // type list_head
    #[osi(osi_type)]
    pub sibling: ListHead, // type list_head
}

impl TaskStruct {
    #[allow(dead_code)]
    pub fn get_next_task(&self) -> Option<target_ptr_t> {
        self.tasks
            .get_owning_struct_ptr("task_struct", "tasks", true)
    }

    #[allow(dead_code)]
    pub fn get_prev_task(&self) -> Option<target_ptr_t> {
        self.tasks
            .get_owning_struct_ptr("task_struct", "tasks", false)
    }

    #[allow(dead_code)]
    pub fn get_next_child(&self) -> Option<target_ptr_t> {
        self.children
            .get_owning_struct_ptr("task_struct", "sibling", false)
    }

    #[allow(dead_code)]
    pub fn get_next_sibling(&self) -> Option<target_ptr_t> {
        self.sibling
            .get_owning_struct_ptr("task_struct", "sibling", true)
    }
}

/// # Structure
/// `CosiProc` bundles up useful data and metadata about `task_struct`s.
///     `addr`  is a pointer to the underlying task_struct
///     `task`  is the task_struct we read from the memory
///     `name`  is the name of the process
///     `ppid`  is the pid of the parent task_struct
///     `mm`    is the mm_struct pointed to by task.mm, read from memory
///     `asid`  is the asid of the process
///     `taskd` is task.group_leader
///
///  # Functions
/// `get_next_process` walks task.tasks to find the next process in the process list and returns it as a CosiProc
/// `get_prev_process` walks task.tasks backwards to find the previous process in the process list and returns it as a CosiProc
/// `get_next_child` returns a CosiProc representaion of the process reffered to by task.children.next
/// `get_next_sibling` returns a CosiProc representation of the process reffered to by task.sibling.next
/// `get_init_cosiproc` returns a CosiProc representation of the process pointed to by the init_task symbol
/// `get_current_cosiproc` returns a CosiProc representation of the current process
/// `new` returns a CosiProc representation of a task_struct, given a pointer to that task_struct
/// `get_mappings` returns a CosiMappings representation of modules loaded in process represented by the CosiProc calling this function
#[repr(C)]
#[derive(Debug, Clone)]
pub struct CosiProc {
    /// `addr` is a pointer to the underlying task_struct
    pub addr: target_ptr_t,
    /// `task` is the task_struct we read from the memory
    pub task: TaskStruct,
    /// `name` is the name of the process
    pub name: Box<String>,
    /// `ppid` is the pid of the parent task_struct
    pub ppid: u32,
    /// `mm` is the mm_struct pointed to by task.mm, read from memory
    pub mm: Option<Box<MmStruct>>,
    /// `asid`  is the asid of the process
    pub asid: u32,
    /// `taskd` is task.group_leader
    pub taskd: target_ptr_t,
}

impl CosiProc {
    /// `get_next_process` walks task.tasks to find the next process in the process list and returns it as a CosiProc
    #[allow(dead_code)]
    pub fn get_next_process(&self, cpu: &mut CPUState) -> Option<CosiProc> {
        CosiProc::new(cpu, self.task.get_next_task()?)
    }

    /// `get_prev_process` walks task.tasks backwards to find the previous process in the process list and returns it as a CosiProc
    #[allow(dead_code)]
    pub fn get_prev_process(&self, cpu: &mut CPUState) -> Option<CosiProc> {
        CosiProc::new(cpu, self.task.get_prev_task()?)
    }

    /// `get_next_child` returns a CosiProc representaion of the process reffered to by task.children.next
    pub fn get_next_child(&self, cpu: &mut CPUState) -> Option<CosiProc> {
        CosiProc::new(cpu, self.task.get_next_child()?)
    }

    /// `get_next_sibling` returns a CosiProc representation of the process reffered to by task.sibling.next
    pub fn get_next_sibling(&self, cpu: &mut CPUState) -> Option<CosiProc> {
        CosiProc::new(cpu, self.task.get_next_sibling()?)
    }

    /// `get_init_cosiproc` returns a CosiProc representation of the process pointed to by the init_task symbol
    #[allow(dead_code)]
    pub fn get_init_cosiproc(cpu: &mut CPUState) -> Option<CosiProc> {
        let init_task_addr = find_per_cpu_address(cpu, "init_task").ok()?;
        CosiProc::new(cpu, init_task_addr)
    }

    /// `get_current_cosiproc` returns a CosiProc representation of the current process
    pub fn get_current_cosiproc(cpu: &mut CPUState) -> Option<CosiProc> {
        #[cfg(any(feature = "mips", feature = "mipsel"))] 
        let curr_task_addr = {
            let addr = HWPROCID.get_id(cpu);
            read_guest_type(cpu, addr).unwrap()
        };
        #[cfg(feature = "arm")]
        let curr_task_addr = {
            let kernel_sp = panda::current_ksp(cpu);
            let task_thread_info = kernel_sp & !(0x2000 - 1);
            read_guest_type(cpu, task_thread_info + 0xc).unwrap()
        };
        #[cfg(not(any(feature = "mips", feature = "mipsel", feature = "arm")))]
        let curr_task_addr = {
            match find_per_cpu_address(cpu, "current_task").ok() {
                Some(res) => res,
                None => std::process::exit(0),
            }
        };
        CosiProc::new(cpu, curr_task_addr)
    }

    /// `new` returns a CosiProc representation of a task_struct, given a pointer to that task_struct
    pub fn new(cpu: &mut CPUState, addr: target_ptr_t) -> Option<CosiProc> {
        let task = TaskStruct::osi_read(cpu, addr).ok()?;
        let mm_ptr = task.mm;
        let mm = MmStruct::osi_read(cpu, mm_ptr).ok().map(Box::new);
        let asid = match &mm {
            Some(res) => res.pgd,
            None => 0,
        };

        let comm_data = task.comm;
        let task_comm_len = comm_data
            .iter()
            .position(|&x| x == 0u8)
            .unwrap_or(TASK_COMM_LEN);
        let name = Box::new(String::from_utf8_lossy(&comm_data[..task_comm_len]).into_owned());
        let parent = TaskStruct::osi_read(cpu, task.parent).ok();
        let ppid = match &parent {
            Some(res) => res.pid,
            None => 0,
        };
        let taskd = task.group_leader;

        Some(CosiProc {
            addr,
            task,
            name,
            ppid,
            mm,
            asid,
            taskd,
        })
    }

    /// `get_mappings` returns a CosiMappings representation of modules loaded in process represented by the CosiProc calling this function
    pub fn get_mappings(&self, cpu: &mut CPUState) -> Option<CosiMappings> {
        let taskd = CosiProc::new(cpu, self.taskd)?;

        taskd
            .mm
            .map(|res| CosiMappings::new(cpu, res.mmap))
            .flatten()
    }
}

#[repr(C)]
#[derive(Debug)]
/// # Structure
/// `CosiThread` bundles up useful information about `thread_struct`s
///     `tid` is the pid of the owning process
///     `pid` is the thread group id of the owning process
/// # Functions
/// `get_current_cosithread` returns a CosiThread representation of the current process
pub struct CosiThread {
    /// `tid` is the pid of the owning process
    pub tid: u32,
    /// `pid` is the thread group id of the owning process
    pub pid: u32,
    // Maybe in the future want to have more mature thread_struct represenation
    // but old OSI doesn't use it
}

impl CosiThread {
    /// `get_current_cosithread` returns a CosiThread representation of the current process
    pub fn get_current_cosithread(cpu: &mut CPUState) -> Option<CosiThread> {
        let c_proc = CosiProc::get_current_cosiproc(cpu)?;
        Some(CosiThread {
            tid: c_proc.task.pid,
            pid: c_proc.task.tgid,
        })
    }
}

//#################################################################
//#################### File related structures ####################
//#################################################################

#[repr(C)]
#[derive(OsiType, Debug)]
#[osi(type_name = "callback_head")]
pub struct CallbackHead {
    pub func: target_ptr_t, // type *function
    pub next: target_ptr_t, // type *callback_head
}

#[repr(C)]
#[derive(OsiType, Debug)]
#[osi(type_name = "qstr")]
pub struct Qstr {
    pub unnamed_field_0: u64, // type union {struct { HASH_LEN_DECLARE; }; u64 hash_len;}
    pub name: target_ptr_t,   // type *char
                              //name: [u8; QSTR_NAME_LEN] // trying it this way for easier reading?
}

#[repr(C)]
#[derive(OsiType, Debug)]
#[osi(type_name = "dentry")]
pub struct Dentry {
    pub d_parent: target_ptr_t, // type *dentry
    //d_name: target_ptr_t, // type qstr (struct qstr { union { struct {HASH_LEN_DECLARE;}; u64 hash_len; } const unsigned char *name;})
    #[osi(osi_type)]
    pub d_name: Qstr,
}

#[repr(C)]
#[derive(OsiType, Debug)]
#[osi(type_name = "mount")]
pub struct Mount {
    pub mnt_mountpoint: target_ptr_t, // type *dentry
}

#[repr(C)]
#[derive(OsiType, Debug)]
#[osi(type_name = "vfsmount")]
pub struct VfsMount {
    pub mnt_flags: i32,         // type int
    pub mnt_root: target_ptr_t, // type *dentry
}

#[repr(C)]
#[derive(OsiType, Debug)]
#[osi(type_name = "path")]
pub struct Path {
    pub dentry: target_ptr_t, // type *dentry
    pub mnt: target_ptr_t,    // type *vfsmount
}

#[repr(C)]
#[derive(OsiType, Debug)]
#[osi(type_name = "file")]
pub struct File {
    #[osi(osi_type)]
    pub f_path: Path, // type Path
    pub f_pos: target_ptr_t, // type long long int
}

impl File {
    fn read_dentry_name(&self, cpu: &mut CPUState, is_mnt: bool) -> Option<String> {
        let mut ret = "".to_owned();
        let mut current_dentry_parent = if is_mnt {
            // next read name stuff from vfsmount too
            VfsMount::osi_read(cpu, self.f_path.mnt).ok()?;
            let mount_vol = symbol_table().type_from_name("mount").unwrap();
            let off = mount_vol.fields["mnt"].offset as target_ptr_t;
            let mount_struct = Mount::osi_read(cpu, self.f_path.mnt - off).ok()?;
            mount_struct.mnt_mountpoint
        } else {
            self.f_path.dentry
        };
        let mut current_dentry: target_ptr_t = 0xdead00af;

        while current_dentry_parent != current_dentry {
            current_dentry = current_dentry_parent;
            let dentry_struct = Dentry::osi_read(cpu, current_dentry).ok()?;
            current_dentry_parent = dentry_struct.d_parent;
            let name_ptr = dentry_struct.d_name.name;
            let name = cpu.mem_read_string(name_ptr);

            let term = if ret.is_empty() || is_mnt { "" } else { "/" };

            if &name == "/" || current_dentry == current_dentry_parent {
                ret = name.to_owned() + &ret
            } else {
                ret = name.to_owned() + term + &ret
            }
        }

        match ret.as_str() {
            "/" => Some("".to_owned()),
            _ => Some(ret),
        }
    }

    pub fn read_name(&self, cpu: &mut CPUState) -> Option<String> {
        // read file->path->dentry to get a pointer to the first dentry we want to read;
        let d_name = self.read_dentry_name(cpu, false)?;
        let m_name = self.read_dentry_name(cpu, true)?;
        Some(m_name + &d_name)
    }
}

#[repr(C)]
#[derive(OsiType, Debug)]
#[osi(type_name = "fdtable")]
pub struct Fdtable {
    pub close_on_exec: target_ptr_t, // type *long unsigned int
    pub fd: target_ptr_t,            // type **file
    pub full_fds_bits: target_ptr_t, // type *long unsigned int
    pub max_fds: u32,                // type unsigned int
    pub open_fds: target_ptr_t, // type *long unsigned int | used as a bit vector, if nth bit is set, fd n is open

    // It doesn't seem like we'll need these, but maybe
    //rcu: CallbackHead, // type callbackhead
    pub rcu: target_ptr_t, // placeholder for compilation until I can figure out what to do
}

#[repr(C)]
#[derive(OsiType, Debug)]
#[osi(type_name = "files_struct")]
pub struct FilesStruct {
    pub fd_array: [target_ptr_t; 64], // type *file[] | default length is defined as BITS_IN_LONG, might need to make this smarter/dependant on the system
    pub fdt: target_ptr_t,            // type *fdtable
    #[osi(osi_type)]
    pub fdtab: Fdtable,
}

// Cosi struct for holding and accessing information about a file struct
#[repr(C)]
#[derive(Debug)]
/// # Structure
/// `CosiFile` bundles useful data and metadata about `file`s
///     `addr` is a pointer to the underlying  `file` structure
///     `file_struct` is the underlying `file` read from memory
///     `name` is the name of the file on disk associated with the `file`
///     `fd` is the file descriptor associated with this `file` in the `files_struct` that keeps track of it
/// # Functions
/// `new` returns a `CosiFile` representing the `file` pointed to by a given pointer
pub struct CosiFile {
    /// `addr` is a pointer to the underlying  `file` structure
    pub addr: target_ptr_t,
    /// `file_struct` is the underlying `file` read from memory
    pub file_struct: File,
    /// `name` is the name of the file on disk associated with the `file`
    pub name: Box<String>,
    /// `fd` is the file descriptor associated with this `file` in the `files_struct` that keeps track of it
    pub fd: u32,
}

impl CosiFile {
    /// `new` returns a `CosiFile` representing the `file` pointed to by a given pointer
    pub fn new(cpu: &mut CPUState, addr: target_ptr_t, fd: u32) -> Option<Self> {
        let file = File::osi_read(cpu, addr).ok()?;
        let name = Box::new(file.read_name(cpu)?);
        Some(CosiFile {
            addr,
            file_struct: file,
            name,
            fd,
        })
    }
}

#[derive(Debug)]
/// # Structure
/// `CosiFiles` holds a `Vec` of `CosiFile`s representing all open files for some process
///     `files` is a `Vec` of `CosiFile`s representing the open files of a process
/// # Functions
/// `get_file_from_fd` returns the `CosiFile` with the given file descriptor from `files`
/// `get_current_cosifiles` returns a `CosiFiles` representing all open `file`s of the current process
/// `new` returns a `CosiFiles` representing all open `file`s associated with a `files_struct` at a given pointer
pub struct CosiFiles {
    /// `files` is a `Vec` of `CosiFile`s representing the open files of a process
    pub files: Vec<CosiFile>,
}

impl CosiFiles {
    /// `get_file_from_fd` returns the `CosiFile` with the given file descriptor from `files`
    pub fn file_from_fd(&self, fd: u32) -> Option<&CosiFile> {
        let ret = self.files.iter().find(|x| x.fd == fd)?;
        Some(ret)
    }

    /// `get_current_cosifiles` returns a `CosiFiles` representing all open `file`s of the current process
    pub fn get_current_files(cpu: &mut CPUState) -> Option<CosiFiles> {
        let c_proc = CosiProc::get_current_cosiproc(cpu)?;
        CosiFiles::new(cpu, c_proc.task.files)
    }

    /// `new` returns a `CosiFiles` representing all open `file`s associated with a `files_struct` at a given pointer
    pub fn new(cpu: &mut CPUState, addr: target_ptr_t) -> Option<Self> {
        let mut file_vec = Vec::<CosiFile>::new();
        let files = FilesStruct::osi_read(cpu, addr).ok()?;
        let max_fds = files.fdtab.max_fds;
        let open_fds = u32::read_from_guest(cpu, files.fdtab.open_fds).unwrap();
        let mut fd_ptr = files.fdtab.fd;

        let step = size_of::<target_ptr_t>() as target_ptr_t;
        for idx in 0..max_fds {
            let fd = target_ptr_t::read_from_guest(cpu, fd_ptr).unwrap();
            if fd == 0 {
                break;
            }
            let bv_check = open_fds >> idx;
            if bv_check == 0 {
                break;
            } else if bv_check % 2 == 0 {
                fd_ptr += step;

                continue;
            } else {
                fd_ptr += step;

                if let Some(f_info) = CosiFile::new(cpu, fd, idx) {
                    file_vec.push(f_info);
                }
            }
        }
        Some(CosiFiles { files: file_vec })
    }
}

//#################################################################
//################### Module related structures ###################
//#################################################################

#[repr(C)]
#[derive(OsiType, Debug)]
#[osi(type_name = "vm_area_struct")]
pub struct VmAreaStruct {
    pub vm_mm: target_ptr_t,    // type *mm_struct
    pub vm_start: target_ptr_t, // type long unsigned int
    pub vm_end: target_ptr_t,   // type long unsigned int
    pub vm_next: target_ptr_t,  // type *vm_area_struct
    pub vm_file: target_ptr_t,  // type *file
    pub vm_flags: target_ptr_t, // type long unsigned int
}

/// # Structure
/// `CosiModule` bundles data and metadata associated with a `vm_area_struct`
///     `modd` is a pointer to the underlying `vm_area_struct`
///     `base` is `vm_area_struct.vm_start`
///     `size` is `vm_area_struct.vm_end` - `vm_area_struct.vm_start`
///     `vma` is the underlying `vm_area_struct` read from memory
///     `file` is the path to the file backing the memory region
///     `name` is the name of the file backing the memory region
/// # Functions
/// `new` returns a `CosiModule` representing the `vm_area_struct` at the given address
#[repr(C)]
pub struct CosiModule {
    /// `modd` is a pointer to the underlying `vm_area_struct`
    pub modd: target_ptr_t, // vma_addr
    /// `base` is `vm_area_struct.vm_start`
    pub base: target_ptr_t, // vma_start
    /// `size` is `vm_area_struct.vm_end` - `vm_area_struct.vm_start`
    pub size: target_ptr_t, // vma_end - vma_start
    /// `vma` is the underlying `vm_area_struct` read from memory
    pub vma: VmAreaStruct, // underlying structure
    /// `file` is the path to the file backing the memory region
    pub file: Box<String>, // read_dentry result
    /// `name` is the name of the file backing the memory region
    pub name: Box<String>, // strstr(file, "/") if file backed, else something like [stack] or [heap]
}

impl CosiModule {
    /// `new` returns a `CosiModule` representing the `vm_area_struct` at the given address
    pub fn new(cpu: &mut CPUState, addr: target_ptr_t) -> Option<CosiModule> {
        let vma = VmAreaStruct::osi_read(cpu, addr).ok()?;
        let base = vma.vm_start;
        let size = vma.vm_end - base;
        let (file, name) = match File::osi_read(cpu, vma.vm_file).ok() {
            Some(res) => {
                let fname = res.read_name(cpu)?;
                let n_ret = fname.split('/').last()?;
                (fname.clone(), n_ret.to_owned())
            }
            None => {
                let mm = MmStruct::osi_read(cpu, vma.vm_mm).ok()?;
                let n_ret = if vma.vm_start <= mm.start_brk && vma.vm_end >= mm.brk {
                    "[heap]"
                } else if vma.vm_start <= mm.start_stack && vma.vm_end >= mm.start_stack {
                    "[stack]"
                } else {
                    "[???]"
                };
                ("".to_owned(), n_ret.to_owned())
            }
        };
        Some(CosiModule {
            modd: addr,
            base,
            size,
            vma,
            file: Box::new(file),
            name: Box::new(name),
        })
    }
}

/// # Structure
/// `CosiMappings` holds a `Vec` of `CosiModule`s representing all mapped memory regions for a process
///     `modules` is a `Vec` of `CosiModule`s which each represent a mapped memory region for a process
/// # Functions
/// `new` returns a `CosiMappings` containing `CosiModule`s for all modules discoverable by traversing the `vm_next` linked list of a `vm_area_struct` at the given address
#[repr(C)]
pub struct CosiMappings {
    /// `modules` is a `Vec` of `CosiModule`s which each represent a mapped memory region for a process
    pub modules: Box<Vec<CosiModule>>,
}

impl CosiMappings {
    /// `new` returns a `CosiMappings` containing `CosiModule`s for all modules discoverable by traversing the `vm_next` linked list of a `vm_area_struct` at the given address
    pub fn new(cpu: &mut CPUState, addr: target_ptr_t) -> Option<CosiMappings> {
        let mut modules = Box::new(Vec::new());
        let vma_first = addr;
        let mut vma_current = vma_first;

        while let Some(cur_mod) = CosiModule::new(cpu, vma_current) {
            vma_current = cur_mod.vma.vm_next;
            modules.push(cur_mod);
            if vma_current == 0 || vma_current == vma_first {
                break;
            }
        }

        Some(CosiMappings { modules })
    }
}
