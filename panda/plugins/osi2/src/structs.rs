use panda::prelude::*;
use panda::plugins::osi2::{osi_static, OsiType};

/// Max length of process command (`comm` field in task_struct)
pub const TASK_COMM_LEN: usize = 16;

//#################################################################
//#################### Task related structures ####################
//#################################################################

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
    pub uid: target_ptr_t, // type unsigned int
    pub gid: target_ptr_t, // type unsigned int
    pub euid: target_ptr_t, // type unsigned int
    pub egid: target_ptr_t, // type unsigned int
}

#[derive(OsiType, Debug)]
#[osi(type_name = "mm_struct")]
pub struct MmStruct {
    pub pgd: u32, // type *unnamed_bunch_of_stuff_3
    pub arg_start: target_ptr_t, // type long unsigned int
    pub start_brk: target_ptr_t, // type long unsigned int
    pub brk: target_ptr_t, // type long unsigned int
    pub start_stack: target_ptr_t, // type long unsigned int
}

#[derive(OsiType, Debug)]
#[osi(type_name = "task_struct")]
pub struct TaskStruct {
    // Only one of tasks or next_task will exist as a field
    pub tasks: target_ptr_t, // type list_head
    //next_task: target_ptr_t, // type ??

    pub pid: u32, // type int
    pub tgid: u32, //type int
    pub group_leader: target_ptr_t, // type *task_struct
    pub thread_group: target_ptr_t, // type list_head

    // Only one of real_parent or p_opptr will exist as a field
    pub real_parent: target_ptr_t, // type *task_struct 
    //p_opptr: target_ptr_t, // type ??

    // Only one of parent or p_pptr will exist as a field
    pub parent: target_ptr_t, // type *task_struct
    //p_pptr: target_ptr_t, // type ??

    pub mm: target_ptr_t, // type *mm_struct
    pub stack: target_ptr_t, // type *void
    pub real_cred: target_ptr_t, // type *cred
    pub cred: target_ptr_t, // type *cred
    pub comm: [u8; TASK_COMM_LEN], // type char[]
    pub files: target_ptr_t, // type *files_struct
    pub start_time: target_ptr_t, // type long long unsigned int

}

#[derive(Debug)]
pub struct OsiProc {
    pub asid: u32,
    pub start_time: target_ptr_t,
    pub name: String,
    pub pid: u32,
    pub ppid: u32,
    pub taskd: target_ptr_t,
}

#[derive(Debug)]
pub struct OsiThread {
    pub tid: u32,
    pub pid: u32,
}

//#################################################################
//#################### File related structures ####################
//#################################################################
#[derive(OsiType, Debug)]
#[osi(type_name = "vm_area_struct")]
pub struct VmAreaStruct {
    pub vm_mm: target_ptr_t, // type *mm_struct
    pub vm_start: target_ptr_t, // type long unsigned int
    pub vm_end: target_ptr_t, // type long unsigned int
    pub vm_next: target_ptr_t, // type *vm_area_struct
    pub vm_file: target_ptr_t, // type *file
    pub vm_flags: target_ptr_t, // type long unsigned int
}

#[derive(OsiType, Debug)]
#[osi(type_name = "callback_head")]
pub struct CallbackHead {
    pub func: target_ptr_t, // type *function
    pub next: target_ptr_t, // type *callback_head
}
pub const QSTR_NAME_LEN: usize = 256;

#[derive(OsiType, Debug)]
#[osi(type_name = "qstr")]
pub struct Qstr {
    pub unnamed_field_0: u64, // type union {struct { HASH_LEN_DECLARE; }; u64 hash_len;}
    pub name: target_ptr_t, // type *char
    //name: [u8; QSTR_NAME_LEN] // trying it this way for easier reading?
}

#[derive(OsiType, Debug)]
#[osi(type_name = "dentry")]
pub struct Dentry {
    pub d_parent: target_ptr_t, // type *dentry
    //d_name: target_ptr_t, // type qstr (struct qstr { union { struct {HASH_LEN_DECLARE;}; u64 hash_len; } const unsigned char *name;})
    #[osi(osi_type)]
    pub d_name: Qstr,
}

#[derive(OsiType, Debug)]
#[osi(type_name = "mount")]
pub struct Mount {
    pub mnt_mountpoint: target_ptr_t, // type *dentry
}

#[derive(OsiType, Debug)]
#[osi(type_name = "vfsmount")]
pub struct VfsMount {
    pub mnt_flags: i32, // type int
    pub mnt_root: target_ptr_t, // type *dentry
    //TODO: see Dentry
    //mnt_sb: SuperBlock, // type SuperBlock
}

#[derive(OsiType, Debug)]
#[osi(type_name = "path")]
pub struct Path {
    pub dentry: target_ptr_t, // type *dentry
    pub mnt: target_ptr_t, // type *vfsmount
}

#[derive(OsiType, Debug)]
#[osi(type_name = "file")]
pub struct File {
    #[osi(osi_type)]
    pub f_path: Path, // type Path
    pub f_pos: target_ptr_t, // type long long int
}

#[derive(OsiType, Debug)]
#[osi(type_name = "fdtable")]
pub struct Fdtable {
    pub close_on_exec: target_ptr_t, // type *long unsigned int
    pub fd: target_ptr_t, // type **file
    pub full_fds_bits: target_ptr_t, // type *long unsigned int
    pub max_fds: u32, // type unsigned int
    pub open_fds: target_ptr_t, // type *long unsigned int | used as a bit vector, if nth bit is set, fd n is open

    // It doesn't seem like we'll need these, but maybe
    //rcu: CallbackHead, // type callbackhead
    pub rcu: target_ptr_t, // placeholder for compilation until I can figure out what to do
}

#[derive(OsiType, Debug)]
#[osi(type_name = "files_struct")]
pub struct FilesStruct {
    pub fd_array: [target_ptr_t; 64], // type *file[] | default length is defined as BITS_IN_LONG, might need to make this smarter/dependant on the system
    pub fdt: target_ptr_t, // type *fdtable
}

#[derive(Debug)]
pub struct OsiFile {
    pub fs_struct: target_ptr_t,
    pub name: String,
    pub f_pos: target_ptr_t,
    pub fd: u32,

}

#[derive(Debug)]
pub struct OsiFiles {
    pub files: Vec<OsiFile>,
}
