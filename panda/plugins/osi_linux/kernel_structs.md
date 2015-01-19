# Kernel structs quick notes

Sketch of some of the structures used for Linux OS introspection. Only relevant fields appear in the sketch. Exact offsets have to be extracted for each kernel variant using the [kernelinfo](utils/kernelinfo) module.

<big><pre style="line-height: 90%; font-size: 13px;">struct task\_struct {        /\* [sched.h][task_struct] \*/
    void \*stack;            /\* pointer to process task \*/
    struct mm\_struct \*mm {{ /\* memory descriptor: [mm_types.h][mm_struct], pp353 \*/
        pgd_t \*pgd;                     /\* page directory \*/
        struct vm\_area\_struct \*mmap {{  /\* memory regions list: [mm_types.h][vm_area_struct] \*/
            struct mm\_struct \*vm\_mm;    /\* address space we belong to (not used for OSI) \*/
            struct vm_area_struct \*vm\_next, \*vm\_prev; /\* list of VM areas, sorted by address \*/
            unsigned long vm\_start;     /\* start address within vm_mm \*/
            unsigned long vm\_end;       /\* first byte after our end within vm_mm \*/
            unsigned long vm\_flags;     /\* RWXS flags \*/
            struct file \*vm\_file {{     /\* file we map to (can be NULL): [fs.h][file], pp471 */
                struct path f\_path {{   /\* not pointer!: [path.h][path] \*/
                    struct vfsmount \*mnt {{    /\* mounted fs containing file: [mount.h][vfsmount] \*/
                        struct dentry *mnt_mountpoint; /\* dentry of mountpoint: [dcache.h][dentry], pp475 \*/
                        struct dentry *mnt_root; /\* root of the mounted tree: [dcache.h][dentry], pp475 \*/
                    }};
                    struct dentry \*dentry {{    /\* where file is located on fs: [dcache.h][dentry], pp475 \*/
                        struct qstr d_name {{   /\* not pointer!: [dcache.h][qstr] \*/
                        	unsigned int len;
                            const unsigned char \*name;
                        }};
                        unsigned char d\_iname[DNAME\_INLINE\_LEN]; /\* should not be used directly! when the name is small enough, d_name->name will point here. \*/  
                    }}; /\* dentry \*/
                }}; /\* path /*
                #define f\_dentry f\_path.dentry  /\* pseudo-member \*/
                #define f\_vfsmnt f\_path.mnt     /\* pseudo-member \*/
            }}; /\* file \*/
        }}; /\* vm\_area\_struct \*/
    }}; /\* mm\_struct \*/
} /\* task\_struct \*/
</pre></big>


[task_struct]: https://github.com/torvalds/linux/blob/v3.2/include/linux/sched.h#L1220
[mm_struct]: https://github.com/torvalds/linux/blob/v3.2/include/linux/mm_types.h#L289
[vm_area_struct]: https://github.com/torvalds/linux/blob/v3.2/include/linux/mm_types.h#L201
[file]: https://github.com/torvalds/linux/blob/v3.2/include/linux/fs.h#L964
[path]: https://github.com/torvalds/linux/blob/v3.2/include/linux/path.h#L7
[vfsmount]: https://github.com/torvalds/linux/blob/v3.2/include/linux/mount.h#L55
[dentry]: https://github.com/torvalds/linux/blob/v3.2/include/linux/dcache.h#L116
[qstr]: https://github.com/torvalds/linux/blob/v3.2/include/linux/dcache.h#L35
