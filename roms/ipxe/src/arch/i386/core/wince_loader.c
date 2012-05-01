#define LOAD_DEBUG	0

static int get_x_header(unsigned char *data, unsigned long now);
static void jump_2ep();
static unsigned char ce_signature[] = {'B', '0', '0', '0', 'F', 'F', '\n',};
static char ** ep;

#define BOOT_ARG_PTR_LOCATION 0x001FFFFC

typedef struct _BOOT_ARGS{
	unsigned char ucVideoMode;
	unsigned char ucComPort;
	unsigned char ucBaudDivisor;
	unsigned char ucPCIConfigType;
	
	unsigned long dwSig;
	#define BOOTARG_SIG 0x544F4F42
	unsigned long dwLen;
	
	unsigned char ucLoaderFlags;
	unsigned char ucEshellFlags;
	unsigned char ucEdbgAdapterType;
	unsigned char ucEdbgIRQ;
	
	unsigned long dwEdbgBaseAddr;
	unsigned long dwEdbgDebugZone;	
	unsigned long dwDHCPLeaseTime;
	unsigned long dwEdbgFlags;
	
	unsigned long dwEBootFlag;
	unsigned long dwEBootAddr;
	unsigned long dwLaunchAddr;
	
	unsigned long pvFlatFrameBuffer;
	unsigned short vesaMode;
	unsigned short cxDisplayScreen;
	unsigned short cyDisplayScreen;
	unsigned short cxPhysicalScreen;
	unsigned short cyPhysicalScreen;
	unsigned short cbScanLineLength;
	unsigned short bppScreen;
	
	unsigned char RedMaskSize;
	unsigned char REdMaskPosition;
	unsigned char GreenMaskSize;
	unsigned char GreenMaskPosition;
	unsigned char BlueMaskSize;
	unsigned char BlueMaskPosition;
} BOOT_ARGS;

BOOT_ARGS BootArgs;

static struct segment_info{
	unsigned long addr;		// Section Address
	unsigned long size;		// Section Size
	unsigned long checksum;		// Section CheckSum
} X;

#define PSIZE	(1500)			//Max Packet Size
#define DSIZE  (PSIZE+12)
static unsigned long dbuffer_available =0;
static unsigned long not_loadin =0;
static unsigned long d_now =0;

unsigned long entry;
static unsigned long ce_curaddr;


static sector_t ce_loader(unsigned char *data, unsigned int len, int eof);
static os_download_t wince_probe(unsigned char *data, unsigned int len)
{
	if (strncmp(ce_signature, data, sizeof(ce_signature)) != 0) {
		return 0;
	}
	printf("(WINCE)");
	return ce_loader;
}

static sector_t ce_loader(unsigned char *data, unsigned int len, int eof)
{
	static unsigned char dbuffer[DSIZE];
	int this_write = 0;
	static int firsttime = 1;

	/*
	 *	new packet in, we have to 
	 *	[1] copy data to dbuffer,
	 *
	 *	update...
	 *	[2]  dbuffer_available
	 */
	memcpy( (dbuffer+dbuffer_available), data, len);	//[1]
	dbuffer_available += len;	// [2]
	len = 0;

	d_now = 0;
	
#if 0
	printf("dbuffer_available =%ld \n", dbuffer_available);
#endif 
	
	if (firsttime) 
	{
		d_now = sizeof(ce_signature);
		printf("String Physical Address = %lx \n", 
			*(unsigned long *)(dbuffer+d_now));
		
		d_now += sizeof(unsigned long);
		printf("Image Size = %ld [%lx]\n", 
			*(unsigned long *)(dbuffer+d_now), 
			*(unsigned long *)(dbuffer+d_now));
		
		d_now += sizeof(unsigned long);
		dbuffer_available -= d_now;			
		
		d_now = (unsigned long)get_x_header(dbuffer, d_now);
		firsttime = 0;
	}
	
	if (not_loadin == 0)
	{
		d_now = get_x_header(dbuffer, d_now);
	}
	
	while ( not_loadin > 0 )
	{
		/* dbuffer do not have enough data to loading, copy all */
#if LOAD_DEBUG
		printf("[0] not_loadin = [%ld], dbuffer_available = [%ld] \n", 
			not_loadin, dbuffer_available);
		printf("[0] d_now = [%ld] \n", d_now);
#endif
		
		if( dbuffer_available <= not_loadin)
		{
			this_write = dbuffer_available ;
			memcpy(phys_to_virt(ce_curaddr), (dbuffer+d_now), this_write );
			ce_curaddr += this_write;
			not_loadin -= this_write;
			
			/* reset index and available in the dbuffer */
			dbuffer_available = 0;
			d_now = 0;
#if LOAD_DEBUG
			printf("[1] not_loadin = [%ld], dbuffer_available = [%ld] \n", 
				not_loadin, dbuffer_available);
			printf("[1] d_now = [%ld], this_write = [%d] \n", 
				d_now, this_write);
#endif
				
			// get the next packet...
			return (0);
		}
			
		/* dbuffer have more data then loading ... , copy partital.... */
		else
		{
			this_write = not_loadin;
			memcpy(phys_to_virt(ce_curaddr), (dbuffer+d_now), this_write);
			ce_curaddr += this_write;
			not_loadin = 0;
			
			/* reset index and available in the dbuffer */
			dbuffer_available -= this_write;
			d_now += this_write;
#if LOAD_DEBUG
			printf("[2] not_loadin = [%ld], dbuffer_available = [%ld] \n", 
				not_loadin, dbuffer_available);
			printf("[2] d_now = [%ld], this_write = [%d] \n\n", 
				d_now, this_write);
#endif
			
			/* dbuffer not empty, proceed processing... */
			
			// don't have enough data to get_x_header..
			if ( dbuffer_available < (sizeof(unsigned long) * 3) )
			{
//				printf("we don't have enough data remaining to call get_x. \n");
				memcpy( (dbuffer+0), (dbuffer+d_now), dbuffer_available);
				return (0);
			}
			else
			{
#if LOAD_DEBUG				
				printf("with remaining data to call get_x \n");
				printf("dbuffer available = %ld , d_now = %ld\n", 
					dbuffer_available, d_now);
#endif					
				d_now = get_x_header(dbuffer, d_now);
			}
		}
	}
	return (0);
}

static int get_x_header(unsigned char *dbuffer, unsigned long now)
{
	X.addr = *(unsigned long *)(dbuffer + now);
	X.size = *(unsigned long *)(dbuffer + now + sizeof(unsigned long));
	X.checksum = *(unsigned long *)(dbuffer + now + sizeof(unsigned long)*2);

	if (X.addr == 0)
	{
		entry = X.size;
		done(1);
		printf("Entry Point Address = [%lx] \n", entry);
		jump_2ep();		
	}

	if (!prep_segment(X.addr, X.addr + X.size, X.addr + X.size, 0, 0)) {
		longjmp(restart_etherboot, -2);
	}

	ce_curaddr = X.addr;
	now += sizeof(unsigned long)*3;

	/* re-calculate dbuffer available... */
	dbuffer_available -= sizeof(unsigned long)*3;

	/* reset index of this section */
	not_loadin = X.size;
	
#if 1
	printf("\n");
	printf("\t Section Address = [%lx] \n", X.addr);
	printf("\t Size = %d [%lx]\n", X.size, X.size);
	printf("\t Checksum = %ld [%lx]\n", X.checksum, X.checksum);
#endif
#if LOAD_DEBUG
	printf("____________________________________________\n");
	printf("\t dbuffer_now = %ld \n", now);
	printf("\t dbuffer available = %ld \n", dbuffer_available);
	printf("\t not_loadin = %ld \n", not_loadin);
#endif

	return now;
}

static void jump_2ep()
{
	BootArgs.ucVideoMode = 1;
	BootArgs.ucComPort = 1;
	BootArgs.ucBaudDivisor = 1;
	BootArgs.ucPCIConfigType = 1;	// do not fill with 0
	
	BootArgs.dwSig = BOOTARG_SIG;
	BootArgs.dwLen = sizeof(BootArgs);
	
	if(BootArgs.ucVideoMode == 0)
	{
		BootArgs.cxDisplayScreen = 640;
		BootArgs.cyDisplayScreen = 480;
		BootArgs.cxPhysicalScreen = 640;
		BootArgs.cyPhysicalScreen = 480;
		BootArgs.bppScreen = 16;
		BootArgs.cbScanLineLength  = 1024;
		BootArgs.pvFlatFrameBuffer = 0x800a0000;	// ollie say 0x98000000
	}	
	else if(BootArgs.ucVideoMode != 0xFF)
	{
		BootArgs.cxDisplayScreen = 0;
		BootArgs.cyDisplayScreen = 0;
		BootArgs.cxPhysicalScreen = 0;
		BootArgs.cyPhysicalScreen = 0;
		BootArgs.bppScreen = 0;
		BootArgs.cbScanLineLength  = 0;
		BootArgs.pvFlatFrameBuffer = 0;	
	}

	ep = phys_to_virt(BOOT_ARG_PTR_LOCATION);
	*ep= virt_to_phys(&BootArgs);
	xstart32(entry);
}
