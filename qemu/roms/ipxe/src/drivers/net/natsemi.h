FILE_LICENCE ( GPL_ANY );

#define NATSEMI_HW_TIMEOUT 400

#define TX_RING_SIZE 4
#define NUM_RX_DESC  4
#define RX_BUF_SIZE 1536
#define OWN       0x80000000
#define DSIZE     0x00000FFF
#define CRC_SIZE  4

struct natsemi_tx {
	uint32_t link;
	uint32_t cmdsts;
	uint32_t bufptr;
};

struct natsemi_rx {
	uint32_t link;
	uint32_t cmdsts;
	uint32_t bufptr;
};

struct natsemi_private {
	unsigned short ioaddr;
	unsigned short tx_cur;
	unsigned short tx_dirty;
	unsigned short rx_cur;
	struct natsemi_tx tx[TX_RING_SIZE];
	struct natsemi_rx rx[NUM_RX_DESC];

	/* need to add iobuf as we cannot free iobuf->data in close without this 
	 * alternatively substracting sizeof(head) and sizeof(list_head) can also 
	 * give the same.
	 */
	struct io_buffer *iobuf[NUM_RX_DESC];

	/* netdev_tx_complete needs pointer to the iobuf of the data so as to free 
	 * it from the memory.
	 */
	struct io_buffer *tx_iobuf[TX_RING_SIZE];
	struct spi_bit_basher spibit;
	struct spi_device eeprom;
	struct nvo_block nvo;
};

/*
 * Support for fibre connections on Am79C874:
 * This phy needs a special setup when connected to a fibre cable.
 * http://www.amd.com/files/connectivitysolutions/networking/archivednetworking/22235.pdf
 */
#define PHYID_AM79C874	0x0022561b

enum {
	MII_MCTRL	= 0x15,		/* mode control register */
	MII_FX_SEL	= 0x0001,	/* 100BASE-FX (fiber) */
	MII_EN_SCRM	= 0x0004,	/* enable scrambler (tp) */
};



/* values we might find in the silicon revision register */
#define SRR_DP83815_C	0x0302
#define SRR_DP83815_D	0x0403
#define SRR_DP83816_A4	0x0504
#define SRR_DP83816_A5	0x0505

/* NATSEMI: Offsets to the device registers.
 * Unlike software-only systems, device drivers interact with complex hardware.
 * It's not useful to define symbolic names for every register bit in the
 * device.
 */
enum register_offsets {
    ChipCmd      = 0x00, 
    ChipConfig   = 0x04, 
    EECtrl       = 0x08, 
    PCIBusCfg    = 0x0C,
    IntrStatus   = 0x10, 
    IntrMask     = 0x14, 
    IntrEnable   = 0x18,
    TxRingPtr    = 0x20, 
    TxConfig     = 0x24,
    RxRingPtr    = 0x30,
    RxConfig     = 0x34, 
    ClkRun       = 0x3C,
    WOLCmd       = 0x40, 
    PauseCmd     = 0x44,
    RxFilterAddr = 0x48, 
    RxFilterData = 0x4C,
    BootRomAddr  = 0x50, 
    BootRomData  = 0x54, 
    SiliconRev   = 0x58, 
    StatsCtrl    = 0x5C,
    StatsData    = 0x60, 
    RxPktErrs    = 0x60, 
    RxMissed     = 0x68, 
    RxCRCErrs    = 0x64,
    PCIPM        = 0x44,
    PhyStatus    = 0xC0, 
    MIntrCtrl    = 0xC4, 
    MIntrStatus  = 0xC8,

    /* These are from the spec, around page 78... on a separate table. 
     */
    PGSEL        = 0xCC, 
    PMDCSR       = 0xE4, 
    TSTDAT       = 0xFC, 
    DSPCFG       = 0xF4, 
    SDCFG        = 0x8C,
    BasicControl = 0x80,	
    BasicStatus  = 0x84
	    
};

/* the values for the 'magic' registers above (PGSEL=1) */
#define PMDCSR_VAL	0x189c	/* enable preferred adaptation circuitry */
#define TSTDAT_VAL	0x0
#define DSPCFG_VAL	0x5040
#define SDCFG_VAL	0x008c	/* set voltage thresholds for Signal Detect */
#define DSPCFG_LOCK	0x20	/* coefficient lock bit in DSPCFG */
#define DSPCFG_COEF	0x1000	/* see coefficient (in TSTDAT) bit in DSPCFG */
#define TSTDAT_FIXED	0xe8	/* magic number for bad coefficients */

/* Bit in ChipCmd.
 */
enum ChipCmdBits {
    ChipReset = 0x100, 
    RxReset   = 0x20, 
    TxReset   = 0x10, 
    RxOff     = 0x08, 
    RxOn      = 0x04,
    TxOff     = 0x02, 
    TxOn      = 0x01
};

enum ChipConfig_bits {
	CfgPhyDis		= 0x200,
	CfgPhyRst		= 0x400,
	CfgExtPhy		= 0x1000,
	CfgAnegEnable		= 0x2000,
	CfgAneg100		= 0x4000,
	CfgAnegFull		= 0x8000,
	CfgAnegDone		= 0x8000000,
	CfgFullDuplex		= 0x20000000,
	CfgSpeed100		= 0x40000000,
	CfgLink			= 0x80000000,
};


/* Bits in the RxMode register.
 */
enum rx_mode_bits {
    AcceptErr          = 0x20,
    AcceptRunt         = 0x10,
    AcceptBroadcast    = 0xC0000000,
    AcceptMulticast    = 0x00200000, 
    AcceptAllMulticast = 0x20000000,
    AcceptAllPhys      = 0x10000000, 
    AcceptMyPhys       = 0x08000000,
    RxFilterEnable     = 0x80000000
};

/* Bits in network_desc.status
 */
enum desc_status_bits {
    DescOwn   = 0x80000000, 
    DescMore  = 0x40000000, 
    DescIntr  = 0x20000000,
    DescNoCRC = 0x10000000,
    DescPktOK = 0x08000000, 
    RxTooLong = 0x00400000
};

/*Bits in Interrupt Mask register
 */
enum Intr_mask_register_bits {
    RxOk       = 0x001,
    RxErr      = 0x004,
    TxOk       = 0x040,
    TxErr      = 0x100 
};	

enum MIntrCtrl_bits {
  MICRIntEn               = 0x2,
};

/* CFG bits [13:16] [18:23] */
#define CFG_RESET_SAVE 0xfde000
/* WCSR bits [0:4] [9:10] */
#define WCSR_RESET_SAVE 0x61f
/* RFCR bits [20] [22] [27:31] */
#define RFCR_RESET_SAVE 0xf8500000;

/* Delay between EEPROM clock transitions.
   No extra delay is needed with 33Mhz PCI, but future 66Mhz access may need
   a delay. */
#define eeprom_delay(ee_addr)   inl(ee_addr)

enum EEPROM_Ctrl_Bits {
	EE_ShiftClk   = 0x04,
	EE_DataIn     = 0x01,
	EE_ChipSelect = 0x08,
	EE_DataOut    = 0x02
};

#define EE_Write0 (EE_ChipSelect)
#define EE_Write1 (EE_ChipSelect | EE_DataIn)

/* The EEPROM commands include the alway-set leading bit. */
enum EEPROM_Cmds {
  EE_WriteCmd=(5 << 6), EE_ReadCmd=(6 << 6), EE_EraseCmd=(7 << 6),
};

/*  EEPROM access , values are devices specific
 */
#define EE_CS		0x08	/* EEPROM chip select */
#define EE_SK		0x04	/* EEPROM shift clock */
#define EE_DI		0x01	/* Data in */
#define EE_DO		0x02	/* Data out */

/* Offsets within EEPROM (these are word offsets)
 */
#define EE_MAC 7
#define EE_REG  EECtrl

static const uint8_t natsemi_ee_bits[] = {
	[SPI_BIT_SCLK]	= EE_SK,
	[SPI_BIT_MOSI]	= EE_DI,
	[SPI_BIT_MISO]	= EE_DO,
	[SPI_BIT_SS(0)]	= EE_CS,
};

