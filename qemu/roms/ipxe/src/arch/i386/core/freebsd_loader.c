/* bootinfo */
#define BOOTINFO_VERSION 1
#define NODEV           (-1)    /* non-existent device */
#define PAGE_SHIFT      12              /* LOG2(PAGE_SIZE) */
#define PAGE_SIZE       (1<<PAGE_SHIFT) /* bytes/page */
#define PAGE_MASK       (PAGE_SIZE-1)
#define N_BIOS_GEOM     8

struct bootinfo {
        unsigned int            bi_version;
        const unsigned char     *bi_kernelname;
        struct nfs_diskless     *bi_nfs_diskless;
                                /* End of fields that are always present. */
#define bi_endcommon            bi_n_bios_used
        unsigned int            bi_n_bios_used;
        unsigned long           bi_bios_geom[N_BIOS_GEOM];
        unsigned int            bi_size;
        unsigned char           bi_memsizes_valid;
        unsigned char           bi_pad[3];
        unsigned long           bi_basemem;
        unsigned long           bi_extmem;
        unsigned long           bi_symtab;
        unsigned long           bi_esymtab;
	/* Note that these are in the FreeBSD headers but were not here... */
	unsigned long           bi_kernend;		/* end of kernel space */
	unsigned long           bi_envp;		/* environment */
	unsigned long           bi_modulep;		/* preloaded modules */
};

static struct bootinfo bsdinfo;

#ifdef ELF_IMAGE
static Elf32_Shdr *shdr;	/* To support the FreeBSD kludge! */
static Address symtab_load;
static Address symstr_load;
static int symtabindex;
static int symstrindex;
#endif

static enum {
	Unknown, Tagged, Aout, Elf, Aout_FreeBSD, Elf_FreeBSD,
} image_type = Unknown;

static unsigned int off;


#ifdef ELF_IMAGE
static void elf_freebsd_probe(void)
{
	image_type = Elf;
	if (	(estate.e.elf32.e_entry & 0xf0000000) && 
		(estate.e.elf32.e_type == ET_EXEC))
	{
		image_type = Elf_FreeBSD;
		printf("/FreeBSD");
		off = -(estate.e.elf32.e_entry & 0xff000000);
		estate.e.elf32.e_entry += off;
	}
	/* Make sure we have a null to start with... */
	shdr = 0;
	
	/* Clear the symbol index values... */
	symtabindex = -1;
	symstrindex = -1;
	
	/* ...and the load addresses of the symbols  */
	symtab_load = 0;
	symstr_load = 0;
}

static void elf_freebsd_fixup_segment(void)
{
	if (image_type == Elf_FreeBSD) {
		estate.p.phdr32[estate.segment].p_paddr += off;
	}
}

static void elf_freebsd_find_segment_end(void)
{
	/* Count the bytes read even for the last block
	 * as we will need to know where the last block
	 * ends in order to load the symbols correctly.
	 * (plus it could be useful elsewhere...)
	 * Note that we need to count the actual size,
	 * not just the end of the disk image size.
	 */
	estate.curaddr += 
		(estate.p.phdr32[estate.segment].p_memsz - 
		estate.p.phdr32[estate.segment].p_filesz);
}

static int elf_freebsd_debug_loader(unsigned int offset)
{
	/* No more segments to be loaded - time to start the
	 * nasty state machine to support the loading of
	 * FreeBSD debug symbols due to the fact that FreeBSD
	 * uses/exports the kernel's debug symbols in order
	 * to make much of the system work!  Amazing (arg!)
	 *
	 * We depend on the fact that for the FreeBSD kernel,
	 * there is only one section of debug symbols and that
	 * the section is after all of the loaded sections in
	 * the file.  This assumes a lot but is somewhat required
	 * to make this code not be too annoying.  (Where do you
	 * load symbols when the code has not loaded yet?)
	 * Since this function is actually just a callback from
	 * the network data transfer code, we need to be able to
	 * work with the data as it comes in.  There is no chance
	 * for doing a seek other than forwards.
	 *
	 * The process we use is to first load the section
	 * headers.  Once they are loaded (shdr != 0) we then
	 * look for where the symbol table and symbol table
	 * strings are and setup some state that we found
	 * them and fall into processing the first one (which
	 * is the symbol table) and after that has been loaded,
	 * we try the symbol strings.  Note that the order is
	 * actually required as the memory image depends on
	 * the symbol strings being loaded starting at the
	 * end of the symbol table.  The kernel assumes this
	 * layout of the image.
	 *
	 * At any point, if we get to the end of the load file
	 * or the section requested is earlier in the file than
	 * the current file pointer, we just end up falling
	 * out of this and booting the kernel without this
	 * information.
	 */

	/* Make sure that the next address is long aligned... */
	/* Assumes size of long is a power of 2... */
	estate.curaddr = (estate.curaddr + sizeof(long) - 1) & ~(sizeof(long) - 1);
	
	/* If we have not yet gotten the shdr loaded, try that */
	if (shdr == 0)
	{
		estate.toread = estate.e.elf32.e_shnum * estate.e.elf32.e_shentsize;
		estate.skip = estate.e.elf32.e_shoff - (estate.loc + offset);
		if (estate.toread)
		{
#if ELF_DEBUG
			printf("shdr *, size %lX, curaddr %lX\n", 
				estate.toread, estate.curaddr);
#endif
			
			/* Start reading at the curaddr and make that the shdr */
			shdr = (Elf32_Shdr *)phys_to_virt(estate.curaddr);
			
			/* Start to read... */
			return 1;
		}
	}
	else
	{
		/* We have the shdr loaded, check if we have found
		 * the indexs where the symbols are supposed to be */
		if ((symtabindex == -1) && (symstrindex == -1))
		{
			int i;
			/* Make sure that the address is page aligned... */
			/* Symbols need to start in their own page(s)... */
			estate.curaddr = (estate.curaddr + 4095) & ~4095;
			
			/* Need to make new indexes... */
			for (i=0; i < estate.e.elf32.e_shnum; i++)
			{
				if (shdr[i].sh_type == SHT_SYMTAB)
				{
					int j;
					for (j=0; j < estate.e.elf32.e_phnum; j++)
					{
						/* Check only for loaded sections */
						if ((estate.p.phdr32[j].p_type | 0x80) == (PT_LOAD | 0x80))
						{
							/* Only the extra symbols */
							if ((shdr[i].sh_offset >= estate.p.phdr32[j].p_offset) &&
								((shdr[i].sh_offset + shdr[i].sh_size) <=
									(estate.p.phdr32[j].p_offset + estate.p.phdr32[j].p_filesz)))
							{
								shdr[i].sh_offset=0;
								shdr[i].sh_size=0;
								break;
							}
						}
					}
					if ((shdr[i].sh_offset != 0) && (shdr[i].sh_size != 0))
					{
						symtabindex = i;
						symstrindex = shdr[i].sh_link;
					}
				}
			}
		}
		
		/* Check if we have a symbol table index and have not loaded it */
		if ((symtab_load == 0) && (symtabindex >= 0))
		{
			/* No symbol table yet?  Load it first... */
			
			/* This happens to work out in a strange way.
			 * If we are past the point in the file already,
			 * we will skip a *large* number of bytes which
			 * ends up bringing us to the end of the file and
			 * an old (default) boot.  Less code and lets
			 * the state machine work in a cleaner way but this
			 * is a nasty side-effect trick... */
			estate.skip = shdr[symtabindex].sh_offset - (estate.loc + offset);
			
			/* And we need to read this many bytes... */
			estate.toread = shdr[symtabindex].sh_size;
			
			if (estate.toread)
			{
#if ELF_DEBUG
				printf("db sym, size %lX, curaddr %lX\n", 
					estate.toread, estate.curaddr);
#endif
				/* Save where we are loading this... */
				symtab_load = estate.curaddr;
				
				*((long *)phys_to_virt(estate.curaddr)) = estate.toread;
				estate.curaddr += sizeof(long);
				
				/* Start to read... */
				return 1;
			}
		}
		else if ((symstr_load == 0) && (symstrindex >= 0))
		{
			/* We have already loaded the symbol table, so
			 * now on to the symbol strings... */
			
			
			/* Same nasty trick as above... */
			estate.skip = shdr[symstrindex].sh_offset - (estate.loc + offset);
			
			/* And we need to read this many bytes... */
			estate.toread = shdr[symstrindex].sh_size;
			
			if (estate.toread)
			{
#if ELF_DEBUG
				printf("db str, size %lX, curaddr %lX\n", 
					estate.toread, estate.curaddr);
#endif
				/* Save where we are loading this... */
				symstr_load = estate.curaddr;
				
				*((long *)phys_to_virt(estate.curaddr)) = estate.toread;
				estate.curaddr += sizeof(long);
				
				/* Start to read... */
				return 1;
			}
		}
	}
	/* all done */
	return 0;
}

static void elf_freebsd_boot(unsigned long entry) 
{
	if (image_type != Elf_FreeBSD)
		return;

	memset(&bsdinfo, 0, sizeof(bsdinfo));
	bsdinfo.bi_basemem = meminfo.basememsize;
	bsdinfo.bi_extmem = meminfo.memsize;
	bsdinfo.bi_memsizes_valid = 1;
	bsdinfo.bi_version = BOOTINFO_VERSION;
	bsdinfo.bi_kernelname = virt_to_phys(KERNEL_BUF);
	bsdinfo.bi_nfs_diskless = NULL;
	bsdinfo.bi_size = sizeof(bsdinfo);
#define RB_BOOTINFO     0x80000000      /* have `struct bootinfo *' arg */  
	if(freebsd_kernel_env[0] != '\0'){
		freebsd_howto |= RB_BOOTINFO;
		bsdinfo.bi_envp = (unsigned long)freebsd_kernel_env;
	}
	
	/* Check if we have symbols loaded, and if so,
	 * made the meta_data needed to pass those to
	 * the kernel. */
	if ((symtab_load !=0) && (symstr_load != 0))
	{
		unsigned long *t;
		
		bsdinfo.bi_symtab = symtab_load;
		
		/* End of symbols (long aligned...) */
		/* Assumes size of long is a power of 2... */
		bsdinfo.bi_esymtab = (symstr_load +
			sizeof(long) +
			*((long *)phys_to_virt(symstr_load)) +
			sizeof(long) - 1) & ~(sizeof(long) - 1);
		
		/* Where we will build the meta data... */
		t = phys_to_virt(bsdinfo.bi_esymtab);
		
#if ELF_DEBUG
		printf("Metadata at %lX\n",t);
#endif
		
		/* Set up the pointer to the memory... */
		bsdinfo.bi_modulep = virt_to_phys(t);
		
		/* The metadata structure is an array of 32-bit
		 * words where we store some information about the
		 * system.  This is critical, as FreeBSD now looks
		 * only for the metadata for the extended symbol
		 * information rather than in the bootinfo.
		 */
		/* First, do the kernel name and the kernel type */
		/* Note that this assumed x86 byte order... */
		
		/* 'kernel\0\0' */
		*t++=MODINFO_NAME; *t++= 7; *t++=0x6E72656B; *t++=0x00006C65;
		
		/* 'elf kernel\0\0' */
		*t++=MODINFO_TYPE; *t++=11; *t++=0x20666C65; *t++=0x6E72656B; *t++ = 0x00006C65;
		
		/* Now the symbol start/end - note that they are
		 * here in local/physical address - the Kernel
		 * boot process will relocate the addresses. */
		*t++=MODINFOMD_SSYM | MODINFO_METADATA; *t++=sizeof(*t); *t++=bsdinfo.bi_symtab;
		*t++=MODINFOMD_ESYM | MODINFO_METADATA; *t++=sizeof(*t); *t++=bsdinfo.bi_esymtab;
		
		*t++=MODINFO_END; *t++=0; /* end of metadata */
		
		/* Since we have symbols we need to make
		 * sure that the kernel knows its own end
		 * of memory...  It is not _end but after
		 * the symbols and the metadata... */
		bsdinfo.bi_kernend = virt_to_phys(t);
		
		/* Signal locore.s that we have a valid bootinfo
		 * structure that was completely filled in. */
		freebsd_howto |= 0x80000000;
	}
	
	xstart32(entry, freebsd_howto, NODEV, 0, 0, 0, 
		virt_to_phys(&bsdinfo), 0, 0, 0);
	longjmp(restart_etherboot, -2);
}
#endif

#ifdef AOUT_IMAGE
static void aout_freebsd_probe(void)
{
	image_type = Aout;
	if (((astate.head.a_midmag >> 16) & 0xffff) == 0) {
		/* Some other a.out variants have a different
		 * value, and use other alignments (e.g. 1K),
		 * not the 4K used by FreeBSD.  */
		image_type = Aout_FreeBSD;
		printf("/FreeBSD");
		off = -(astate.head.a_entry & 0xff000000);
		astate.head.a_entry += off;
	}
}

static void aout_freebsd_boot(void)
{
	if (image_type == Aout_FreeBSD) {
		memset(&bsdinfo, 0, sizeof(bsdinfo));
		bsdinfo.bi_basemem = meminfo.basememsize;
		bsdinfo.bi_extmem = meminfo.memsize;
		bsdinfo.bi_memsizes_valid = 1;
		bsdinfo.bi_version = BOOTINFO_VERSION;
		bsdinfo.bi_kernelname = virt_to_phys(KERNEL_BUF);
		bsdinfo.bi_nfs_diskless = NULL;
		bsdinfo.bi_size = sizeof(bsdinfo);
		xstart32(astate.head.a_entry, freebsd_howto, NODEV, 0, 0, 0, 
			virt_to_phys(&bsdinfo), 0, 0, 0);
		longjmp(restart_etherboot, -2);
	}
}
#endif
