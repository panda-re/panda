/*
 * Bochs/QEMU ACPI DSDT ASL definition
 *
 * Copyright (c) 2006 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
DefinitionBlock (
    "acpi-dsdt.aml",    // Output Filename
    "DSDT",             // Signature
    0x01,               // DSDT Compliance Revision
    "BXPC",             // OEMID
    "BXDSDT",           // TABLE ID
    0x1                 // OEM Revision
    )
{
    Scope (\)
    {
        /* Debug Output */
        OperationRegion (DBG, SystemIO, 0x0402, 0x01)
        Field (DBG, ByteAcc, NoLock, Preserve)
        {
            DBGB,   8,
        }

        /* Debug method - use this method to send output to the QEMU
         * BIOS debug port.  This method handles strings, integers,
         * and buffers.  For example: DBUG("abc") DBUG(0x123) */
        Method(DBUG, 1) {
            ToHexString(Arg0, Local0)
            ToBuffer(Local0, Local0)
            Subtract(SizeOf(Local0), 1, Local1)
            Store(Zero, Local2)
            While (LLess(Local2, Local1)) {
                Store(DerefOf(Index(Local0, Local2)), DBGB)
                Increment(Local2)
            }
            Store(0x0A, DBGB)
        }
    }

    /* PCI Bus definition */
    Scope(\_SB) {
        Device(PCI0) {
            Name (_HID, EisaId ("PNP0A03"))
            Name (_ADR, 0x00)
            Name (_UID, 1)
            Name(_PRT, Package() {
                /* PCI IRQ routing table, example from ACPI 2.0a specification,
                   section 6.2.8.1 */
                /* Note: we provide the same info as the PCI routing
                   table of the Bochs BIOS */
#define prt_slot(nr, lnk0, lnk1, lnk2, lnk3) \
       Package() { nr##ffff, 0, lnk0, 0 }, \
       Package() { nr##ffff, 1, lnk1, 0 }, \
       Package() { nr##ffff, 2, lnk2, 0 }, \
       Package() { nr##ffff, 3, lnk3, 0 }

#define prt_slot0(nr) prt_slot(nr, LNKD, LNKA, LNKB, LNKC)
#define prt_slot1(nr) prt_slot(nr, LNKA, LNKB, LNKC, LNKD)
#define prt_slot2(nr) prt_slot(nr, LNKB, LNKC, LNKD, LNKA)
#define prt_slot3(nr) prt_slot(nr, LNKC, LNKD, LNKA, LNKB)
               prt_slot0(0x0000),
               /* Device 1 is power mgmt device, and can only use irq 9 */
               Package() { 0x0001ffff, 0, LNKS, 0 },
               Package() { 0x0001ffff, 1, LNKB, 0 },
               Package() { 0x0001ffff, 2, LNKC, 0 },
               Package() { 0x0001ffff, 3, LNKD, 0 },
               prt_slot2(0x0002),
               prt_slot3(0x0003),
               prt_slot0(0x0004),
               prt_slot1(0x0005),
               prt_slot2(0x0006),
               prt_slot3(0x0007),
               prt_slot0(0x0008),
               prt_slot1(0x0009),
               prt_slot2(0x000a),
               prt_slot3(0x000b),
               prt_slot0(0x000c),
               prt_slot1(0x000d),
               prt_slot2(0x000e),
               prt_slot3(0x000f),
               prt_slot0(0x0010),
               prt_slot1(0x0011),
               prt_slot2(0x0012),
               prt_slot3(0x0013),
               prt_slot0(0x0014),
               prt_slot1(0x0015),
               prt_slot2(0x0016),
               prt_slot3(0x0017),
               prt_slot0(0x0018),
               prt_slot1(0x0019),
               prt_slot2(0x001a),
               prt_slot3(0x001b),
               prt_slot0(0x001c),
               prt_slot1(0x001d),
               prt_slot2(0x001e),
               prt_slot3(0x001f),
            })

            OperationRegion(PCST, SystemIO, 0xae00, 0x08)
            Field (PCST, DWordAcc, NoLock, WriteAsZeros)
            {
                PCIU, 32,
                PCID, 32,
            }

            OperationRegion(SEJ, SystemIO, 0xae08, 0x04)
            Field (SEJ, DWordAcc, NoLock, WriteAsZeros)
            {
                B0EJ, 32,
            }

            OperationRegion(RMVC, SystemIO, 0xae0c, 0x04)
            Field(RMVC, DWordAcc, NoLock, WriteAsZeros)
            {
                PCRM, 32,
            }

#define hotplug_slot(name, nr) \
            Device (S##name) {                    \
               Name (_ADR, nr##0000)              \
               Method (_EJ0,1) {                  \
                    Store(ShiftLeft(1, nr), B0EJ) \
                    Return (0x0)                  \
               }                                  \
               Name (_SUN, name)                  \
            }

	    hotplug_slot(1, 0x0001)
	    hotplug_slot(2, 0x0002)
	    hotplug_slot(3, 0x0003)
	    hotplug_slot(4, 0x0004)
	    hotplug_slot(5, 0x0005)
	    hotplug_slot(6, 0x0006)
	    hotplug_slot(7, 0x0007)
	    hotplug_slot(8, 0x0008)
	    hotplug_slot(9, 0x0009)
	    hotplug_slot(10, 0x000a)
	    hotplug_slot(11, 0x000b)
	    hotplug_slot(12, 0x000c)
	    hotplug_slot(13, 0x000d)
	    hotplug_slot(14, 0x000e)
	    hotplug_slot(15, 0x000f)
	    hotplug_slot(16, 0x0010)
	    hotplug_slot(17, 0x0011)
	    hotplug_slot(18, 0x0012)
	    hotplug_slot(19, 0x0013)
	    hotplug_slot(20, 0x0014)
	    hotplug_slot(21, 0x0015)
	    hotplug_slot(22, 0x0016)
	    hotplug_slot(23, 0x0017)
	    hotplug_slot(24, 0x0018)
	    hotplug_slot(25, 0x0019)
	    hotplug_slot(26, 0x001a)
	    hotplug_slot(27, 0x001b)
	    hotplug_slot(28, 0x001c)
	    hotplug_slot(29, 0x001d)
	    hotplug_slot(30, 0x001e)
	    hotplug_slot(31, 0x001f)

            Name (_CRS, ResourceTemplate ()
            {
                WordBusNumber (ResourceProducer, MinFixed, MaxFixed, PosDecode,
                    0x0000,             // Address Space Granularity
                    0x0000,             // Address Range Minimum
                    0x00FF,             // Address Range Maximum
                    0x0000,             // Address Translation Offset
                    0x0100,             // Address Length
                    ,, )
                IO (Decode16,
                    0x0CF8,             // Address Range Minimum
                    0x0CF8,             // Address Range Maximum
                    0x01,               // Address Alignment
                    0x08,               // Address Length
                    )
                WordIO (ResourceProducer, MinFixed, MaxFixed, PosDecode, EntireRange,
                    0x0000,             // Address Space Granularity
                    0x0000,             // Address Range Minimum
                    0x0CF7,             // Address Range Maximum
                    0x0000,             // Address Translation Offset
                    0x0CF8,             // Address Length
                    ,, , TypeStatic)
                WordIO (ResourceProducer, MinFixed, MaxFixed, PosDecode, EntireRange,
                    0x0000,             // Address Space Granularity
                    0x0D00,             // Address Range Minimum
                    0xFFFF,             // Address Range Maximum
                    0x0000,             // Address Translation Offset
                    0xF300,             // Address Length
                    ,, , TypeStatic)
                DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed, Cacheable, ReadWrite,
                    0x00000000,         // Address Space Granularity
                    0x000A0000,         // Address Range Minimum
                    0x000BFFFF,         // Address Range Maximum
                    0x00000000,         // Address Translation Offset
                    0x00020000,         // Address Length
                    ,, , AddressRangeMemory, TypeStatic)
                DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed, NonCacheable, ReadWrite,
                    0x00000000,         // Address Space Granularity
                    0xE0000000,         // Address Range Minimum
                    0xFEBFFFFF,         // Address Range Maximum
                    0x00000000,         // Address Translation Offset
                    0x1EC00000,         // Address Length
                    ,, , AddressRangeMemory, TypeStatic)
            })
        }

        Device(HPET) {
            Name(_HID,  EISAID("PNP0103"))
            Name(_UID, 0)
            Method (_STA, 0, NotSerialized) {
                    Return(0x0F)
            }
            Name(_CRS, ResourceTemplate() {
                DWordMemory(
                    ResourceConsumer, PosDecode, MinFixed, MaxFixed,
                    NonCacheable, ReadWrite,
                    0x00000000,
                    0xFED00000,
                    0xFED003FF,
                    0x00000000,
                    0x00000400 /* 1K memory: FED00000 - FED003FF */
                )
            })
        }
    }

    Scope(\_SB.PCI0) {
        Device (VGA) {
                 Name (_ADR, 0x00020000)
                 OperationRegion(PCIC, PCI_Config, Zero, 0x4)
                 Field(PCIC, DWordAcc, NoLock, Preserve) {
                         VEND, 32
                 }
                 Method (_S1D, 0, NotSerialized)
                 {
                         Return (0x00)
                 }
                 Method (_S2D, 0, NotSerialized)
                 {
                         Return (0x00)
                 }
                 Method (_S3D, 0, NotSerialized)
                 {
                         If (LEqual(VEND, 0x1001b36)) {
                                 Return (0x03)           // QXL
                         } Else {
                                 Return (0x00)
                         }
                 }
                 Method(_RMV) { Return (0x00) }
        }

	/* PIIX3 ISA bridge */
        Device (ISA) {
            Name (_ADR, 0x00010000)
            Method(_RMV) { Return (0x00) }


            /* PIIX PCI to ISA irq remapping */
            OperationRegion (P40C, PCI_Config, 0x60, 0x04)

            /* Real-time clock */
            Device (RTC)
            {
                Name (_HID, EisaId ("PNP0B00"))
                Name (_CRS, ResourceTemplate ()
                {
                    IO (Decode16, 0x0070, 0x0070, 0x10, 0x02)
                    IRQNoFlags () {8}
                    IO (Decode16, 0x0072, 0x0072, 0x02, 0x06)
                })
            }

            /* Keyboard seems to be important for WinXP install */
            Device (KBD)
            {
                Name (_HID, EisaId ("PNP0303"))
                Method (_STA, 0, NotSerialized)
                {
                    Return (0x0f)
                }

                Method (_CRS, 0, NotSerialized)
                {
                     Name (TMP, ResourceTemplate ()
                     {
                    IO (Decode16,
                        0x0060,             // Address Range Minimum
                        0x0060,             // Address Range Maximum
                        0x01,               // Address Alignment
                        0x01,               // Address Length
                        )
                    IO (Decode16,
                        0x0064,             // Address Range Minimum
                        0x0064,             // Address Range Maximum
                        0x01,               // Address Alignment
                        0x01,               // Address Length
                        )
                    IRQNoFlags ()
                        {1}
                    })
                    Return (TMP)
                }
            }

	    /* PS/2 mouse */
            Device (MOU)
            {
                Name (_HID, EisaId ("PNP0F13"))
                Method (_STA, 0, NotSerialized)
                {
                    Return (0x0f)
                }

                Method (_CRS, 0, NotSerialized)
                {
                    Name (TMP, ResourceTemplate ()
                    {
                         IRQNoFlags () {12}
                    })
                    Return (TMP)
                }
            }

	    /* PS/2 floppy controller */
	    Device (FDC0)
	    {
	        Name (_HID, EisaId ("PNP0700"))
		Method (_STA, 0, NotSerialized)
		{
		    Return (0x0F)
		}
		Method (_CRS, 0, NotSerialized)
		{
		    Name (BUF0, ResourceTemplate ()
                    {
                        IO (Decode16, 0x03F2, 0x03F2, 0x00, 0x04)
                        IO (Decode16, 0x03F7, 0x03F7, 0x00, 0x01)
                        IRQNoFlags () {6}
                        DMA (Compatibility, NotBusMaster, Transfer8) {2}
                    })
		    Return (BUF0)
		}
	    }

	    /* Parallel port */
	    Device (LPT)
	    {
	        Name (_HID, EisaId ("PNP0400"))
		Method (_STA, 0, NotSerialized)
		{
		    Store (\_SB.PCI0.PX13.DRSA, Local0)
		    And (Local0, 0x80000000, Local0)
		    If (LEqual (Local0, 0))
		    {
			Return (0x00)
		    }
		    Else
		    {
			Return (0x0F)
		    }
		}
		Method (_CRS, 0, NotSerialized)
		{
		    Name (BUF0, ResourceTemplate ()
                    {
			IO (Decode16, 0x0378, 0x0378, 0x08, 0x08)
			IRQNoFlags () {7}
		    })
		    Return (BUF0)
		}
	    }

	    /* Serial Ports */
	    Device (COM1)
	    {
	        Name (_HID, EisaId ("PNP0501"))
		Name (_UID, 0x01)
		Method (_STA, 0, NotSerialized)
		{
		    Store (\_SB.PCI0.PX13.DRSC, Local0)
		    And (Local0, 0x08000000, Local0)
		    If (LEqual (Local0, 0))
		    {
			Return (0x00)
		    }
		    Else
		    {
			Return (0x0F)
		    }
		}
		Method (_CRS, 0, NotSerialized)
		{
		    Name (BUF0, ResourceTemplate ()
                    {
			IO (Decode16, 0x03F8, 0x03F8, 0x00, 0x08)
                	IRQNoFlags () {4}
		    })
		    Return (BUF0)
		}
	    }

	    Device (COM2)
	    {
	        Name (_HID, EisaId ("PNP0501"))
		Name (_UID, 0x02)
		Method (_STA, 0, NotSerialized)
		{
		    Store (\_SB.PCI0.PX13.DRSC, Local0)
		    And (Local0, 0x80000000, Local0)
		    If (LEqual (Local0, 0))
		    {
			Return (0x00)
		    }
		    Else
		    {
			Return (0x0F)
		    }
		}
		Method (_CRS, 0, NotSerialized)
		{
		    Name (BUF0, ResourceTemplate ()
                    {
			IO (Decode16, 0x02F8, 0x02F8, 0x00, 0x08)
                	IRQNoFlags () {3}
		    })
		    Return (BUF0)
		}
	    }
        }

	/* PIIX4 PM */
        Device (PX13) {
	    Name (_ADR, 0x00010003)

	    OperationRegion (P13C, PCI_Config, 0x5c, 0x24)
	    Field (P13C, DWordAcc, NoLock, Preserve)
	    {
		DRSA, 32,
		DRSB, 32,
		DRSC, 32,
		DRSE, 32,
		DRSF, 32,
		DRSG, 32,
		DRSH, 32,
		DRSI, 32,
		DRSJ, 32
	    }
	}

#define gen_pci_device(name, nr)                                \
        Device(SL##name) {                                      \
            Name (_ADR, nr##0000)                               \
            Method (_RMV) {                                     \
                If (And(\_SB.PCI0.PCRM, ShiftLeft(1, nr))) {    \
                    Return (0x1)                                \
                }                                               \
                Return (0x0)                                    \
            }                                                   \
            Name (_SUN, name)                                   \
        }

        /* VGA (slot 1) and ISA bus (slot 2) defined above */
	gen_pci_device(3, 0x0003)
	gen_pci_device(4, 0x0004)
	gen_pci_device(5, 0x0005)
	gen_pci_device(6, 0x0006)
	gen_pci_device(7, 0x0007)
	gen_pci_device(8, 0x0008)
	gen_pci_device(9, 0x0009)
	gen_pci_device(10, 0x000a)
	gen_pci_device(11, 0x000b)
	gen_pci_device(12, 0x000c)
	gen_pci_device(13, 0x000d)
	gen_pci_device(14, 0x000e)
	gen_pci_device(15, 0x000f)
	gen_pci_device(16, 0x0010)
	gen_pci_device(17, 0x0011)
	gen_pci_device(18, 0x0012)
	gen_pci_device(19, 0x0013)
	gen_pci_device(20, 0x0014)
	gen_pci_device(21, 0x0015)
	gen_pci_device(22, 0x0016)
	gen_pci_device(23, 0x0017)
	gen_pci_device(24, 0x0018)
	gen_pci_device(25, 0x0019)
	gen_pci_device(26, 0x001a)
	gen_pci_device(27, 0x001b)
	gen_pci_device(28, 0x001c)
	gen_pci_device(29, 0x001d)
	gen_pci_device(30, 0x001e)
	gen_pci_device(31, 0x001f)
    }

    /* PCI IRQs */
    Scope(\_SB) {
         Field (\_SB.PCI0.ISA.P40C, ByteAcc, NoLock, Preserve)
         {
             PRQ0,   8,
             PRQ1,   8,
             PRQ2,   8,
             PRQ3,   8
         }

        Device(LNKA){
                Name(_HID, EISAID("PNP0C0F"))     // PCI interrupt link
                Name(_UID, 1)
                Name(_PRS, ResourceTemplate(){
                    Interrupt (, Level, ActiveHigh, Shared)
                        { 5, 10, 11 }
                })
                Method (_STA, 0, NotSerialized)
                {
                    Store (0x0B, Local0)
                    If (And (0x80, PRQ0, Local1))
                    {
                         Store (0x09, Local0)
                    }
                    Return (Local0)
                }
                Method (_DIS, 0, NotSerialized)
                {
                    Or (PRQ0, 0x80, PRQ0)
                }
                Method (_CRS, 0, NotSerialized)
                {
                    Name (PRR0, ResourceTemplate ()
                    {
                        Interrupt (, Level, ActiveHigh, Shared)
                            {1}
                    })
                    CreateDWordField (PRR0, 0x05, TMP)
                    Store (PRQ0, Local0)
                    If (LLess (Local0, 0x80))
                    {
                        Store (Local0, TMP)
                    }
                    Else
                    {
                        Store (Zero, TMP)
                    }
                    Return (PRR0)
                }
                Method (_SRS, 1, NotSerialized)
                {
                    CreateDWordField (Arg0, 0x05, TMP)
                    Store (TMP, PRQ0)
                }
        }
        Device(LNKB){
                Name(_HID, EISAID("PNP0C0F"))     // PCI interrupt link
                Name(_UID, 2)
                Name(_PRS, ResourceTemplate(){
                    Interrupt (, Level, ActiveHigh, Shared)
                        { 5, 10, 11 }
                })
                Method (_STA, 0, NotSerialized)
                {
                    Store (0x0B, Local0)
                    If (And (0x80, PRQ1, Local1))
                    {
                         Store (0x09, Local0)
                    }
                    Return (Local0)
                }
                Method (_DIS, 0, NotSerialized)
                {
                    Or (PRQ1, 0x80, PRQ1)
                }
                Method (_CRS, 0, NotSerialized)
                {
                    Name (PRR0, ResourceTemplate ()
                    {
                        Interrupt (, Level, ActiveHigh, Shared)
                            {1}
                    })
                    CreateDWordField (PRR0, 0x05, TMP)
                    Store (PRQ1, Local0)
                    If (LLess (Local0, 0x80))
                    {
                        Store (Local0, TMP)
                    }
                    Else
                    {
                        Store (Zero, TMP)
                    }
                    Return (PRR0)
                }
                Method (_SRS, 1, NotSerialized)
                {
                    CreateDWordField (Arg0, 0x05, TMP)
                    Store (TMP, PRQ1)
                }
        }
        Device(LNKC){
                Name(_HID, EISAID("PNP0C0F"))     // PCI interrupt link
                Name(_UID, 3)
                Name(_PRS, ResourceTemplate(){
                    Interrupt (, Level, ActiveHigh, Shared)
                        { 5, 10, 11 }
                })
                Method (_STA, 0, NotSerialized)
                {
                    Store (0x0B, Local0)
                    If (And (0x80, PRQ2, Local1))
                    {
                         Store (0x09, Local0)
                    }
                    Return (Local0)
                }
                Method (_DIS, 0, NotSerialized)
                {
                    Or (PRQ2, 0x80, PRQ2)
                }
                Method (_CRS, 0, NotSerialized)
                {
                    Name (PRR0, ResourceTemplate ()
                    {
                        Interrupt (, Level, ActiveHigh, Shared)
                            {1}
                    })
                    CreateDWordField (PRR0, 0x05, TMP)
                    Store (PRQ2, Local0)
                    If (LLess (Local0, 0x80))
                    {
                        Store (Local0, TMP)
                    }
                    Else
                    {
                        Store (Zero, TMP)
                    }
                    Return (PRR0)
                }
                Method (_SRS, 1, NotSerialized)
                {
                    CreateDWordField (Arg0, 0x05, TMP)
                    Store (TMP, PRQ2)
                }
        }
        Device(LNKD){
                Name(_HID, EISAID("PNP0C0F"))     // PCI interrupt link
                Name(_UID, 4)
                Name(_PRS, ResourceTemplate(){
                    Interrupt (, Level, ActiveHigh, Shared)
                        { 5, 10, 11 }
                })
                Method (_STA, 0, NotSerialized)
                {
                    Store (0x0B, Local0)
                    If (And (0x80, PRQ3, Local1))
                    {
                         Store (0x09, Local0)
                    }
                    Return (Local0)
                }
                Method (_DIS, 0, NotSerialized)
                {
                    Or (PRQ3, 0x80, PRQ3)
                }
                Method (_CRS, 0, NotSerialized)
                {
                    Name (PRR0, ResourceTemplate ()
                    {
                        Interrupt (, Level, ActiveHigh, Shared)
                            {1}
                    })
                    CreateDWordField (PRR0, 0x05, TMP)
                    Store (PRQ3, Local0)
                    If (LLess (Local0, 0x80))
                    {
                        Store (Local0, TMP)
                    }
                    Else
                    {
                        Store (Zero, TMP)
                    }
                    Return (PRR0)
                }
                Method (_SRS, 1, NotSerialized)
                {
                    CreateDWordField (Arg0, 0x05, TMP)
                    Store (TMP, PRQ3)
                }
        }
        Device(LNKS){
                Name(_HID, EISAID("PNP0C0F"))     // PCI interrupt link
                Name(_UID, 5)
                Name(_PRS, ResourceTemplate(){
                    Interrupt (, Level, ActiveHigh, Shared)
                        { 9 }
                })
                Method (_STA, 0, NotSerialized)
                {
                    Store (0x0B, Local0)
                    If (And (0x80, PRQ0, Local1))
                    {
                         Store (0x09, Local0)
                    }
                    Return (Local0)
                }
                Method (_DIS, 0, NotSerialized)
                {
                    Or (PRQ0, 0x80, PRQ0)
                }
                Method (_CRS, 0, NotSerialized)
                {
                    Name (PRR0, ResourceTemplate ()
                    {
                        Interrupt (, Level, ActiveHigh, Shared)
                            {9}
                    })
                    CreateDWordField (PRR0, 0x05, TMP)
                    Store (PRQ0, Local0)
                    If (LLess (Local0, 0x80))
                    {
                        Store (Local0, TMP)
                    }
                    Else
                    {
                        Store (Zero, TMP)
                    }
                    Return (PRR0)
                }
        }
    }

    /*
     * S3 (suspend-to-ram), S4 (suspend-to-disk) and S5 (power-off) type codes:
     * must match piix4 emulation.
     */
    Name (\_S3, Package (0x04)
    {
        0x01,  /* PM1a_CNT.SLP_TYP */
        0x01,  /* PM1b_CNT.SLP_TYP */
        Zero,  /* reserved */
        Zero   /* reserved */
    })
    Name (\_S4, Package (0x04)
    {
        Zero,  /* PM1a_CNT.SLP_TYP */
        Zero,  /* PM1b_CNT.SLP_TYP */
        Zero,  /* reserved */
        Zero   /* reserved */
    })
    Name (\_S5, Package (0x04)
    {
        Zero,  /* PM1a_CNT.SLP_TYP */
        Zero,  /* PM1b_CNT.SLP_TYP */
        Zero,  /* reserved */
        Zero   /* reserved */
    })

    /* CPU hotplug */
    Scope(\_SB) {
        /* Objects filled in by run-time generated SSDT */
        External(NTFY, MethodObj)
        External(CPON, PkgObj)

        /* Methods called by run-time generated SSDT Processor objects */
        Method (CPMA, 1, NotSerialized) {
            // _MAT method - create an madt apic buffer
            // Local0 = CPON flag for this cpu
            Store(DerefOf(Index(CPON, Arg0)), Local0)
            // Local1 = Buffer (in madt apic form) to return
            Store(Buffer(8) {0x00, 0x08, 0x00, 0x00, 0x00, 0, 0, 0}, Local1)
            // Update the processor id, lapic id, and enable/disable status
            Store(Arg0, Index(Local1, 2))
            Store(Arg0, Index(Local1, 3))
            Store(Local0, Index(Local1, 4))
            Return (Local1)
        }
        Method (CPST, 1, NotSerialized) {
            // _STA method - return ON status of cpu
            // Local0 = CPON flag for this cpu
            Store(DerefOf(Index(CPON, Arg0)), Local0)
            If (Local0) { Return(0xF) } Else { Return(0x0) }
        }
        Method (CPEJ, 2, NotSerialized) {
            // _EJ0 method - eject callback
            Sleep(200)
        }

        /* CPU hotplug notify method */
        OperationRegion(PRST, SystemIO, 0xaf00, 32)
        Field (PRST, ByteAcc, NoLock, Preserve)
        {
            PRS, 256
        }
        Method(PRSC, 0) {
            // Local5 = active cpu bitmap
            Store (PRS, Local5)
            // Local2 = last read byte from bitmap
            Store (Zero, Local2)
            // Local0 = cpuid iterator
            Store (Zero, Local0)
            While (LLess(Local0, SizeOf(CPON))) {
                // Local1 = CPON flag for this cpu
                Store(DerefOf(Index(CPON, Local0)), Local1)
                If (And(Local0, 0x07)) {
                    // Shift down previously read bitmap byte
                    ShiftRight(Local2, 1, Local2)
                } Else {
                    // Read next byte from cpu bitmap
                    Store(DerefOf(Index(Local5, ShiftRight(Local0, 3))), Local2)
                }
                // Local3 = active state for this cpu
                Store(And(Local2, 1), Local3)

                If (LNotEqual(Local1, Local3)) {
                    // State change - update CPON with new state
                    Store(Local3, Index(CPON, Local0))
                    // Do CPU notify
                    If (LEqual(Local3, 1)) {
                        NTFY(Local0, 1)
                    } Else {
                        NTFY(Local0, 3)
                    }
                }
                Increment(Local0)
            }
            Return(One)
        }
    }

    Scope (\_GPE)
    {
        Name(_HID, "ACPI0006")

        Method(_L00) {
            Return(0x01)
        }

#define gen_pci_hotplug(nr)                                       \
            If (And(\_SB.PCI0.PCIU, ShiftLeft(1, nr))) {          \
                Notify(\_SB.PCI0.S##nr, 1)                        \
            }                                                     \
            If (And(\_SB.PCI0.PCID, ShiftLeft(1, nr))) {          \
                Notify(\_SB.PCI0.S##nr, 3)                        \
            }

        Method(_L01) {
            gen_pci_hotplug(1)
            gen_pci_hotplug(2)
            gen_pci_hotplug(3)
            gen_pci_hotplug(4)
            gen_pci_hotplug(5)
            gen_pci_hotplug(6)
            gen_pci_hotplug(7)
            gen_pci_hotplug(8)
            gen_pci_hotplug(9)
            gen_pci_hotplug(10)
            gen_pci_hotplug(11)
            gen_pci_hotplug(12)
            gen_pci_hotplug(13)
            gen_pci_hotplug(14)
            gen_pci_hotplug(15)
            gen_pci_hotplug(16)
            gen_pci_hotplug(17)
            gen_pci_hotplug(18)
            gen_pci_hotplug(19)
            gen_pci_hotplug(20)
            gen_pci_hotplug(21)
            gen_pci_hotplug(22)
            gen_pci_hotplug(23)
            gen_pci_hotplug(24)
            gen_pci_hotplug(25)
            gen_pci_hotplug(26)
            gen_pci_hotplug(27)
            gen_pci_hotplug(28)
            gen_pci_hotplug(29)
            gen_pci_hotplug(30)
            gen_pci_hotplug(31)

            Return (0x01)

        }
        Method(_L02) {
            // CPU hotplug event
            Return(\_SB.PRSC())
        }
        Method(_L03) {
            Return(0x01)
        }
        Method(_L04) {
            Return(0x01)
        }
        Method(_L05) {
            Return(0x01)
        }
        Method(_L06) {
            Return(0x01)
        }
        Method(_L07) {
            Return(0x01)
        }
        Method(_L08) {
            Return(0x01)
        }
        Method(_L09) {
            Return(0x01)
        }
        Method(_L0A) {
            Return(0x01)
        }
        Method(_L0B) {
            Return(0x01)
        }
        Method(_L0C) {
            Return(0x01)
        }
        Method(_L0D) {
            Return(0x01)
        }
        Method(_L0E) {
            Return(0x01)
        }
        Method(_L0F) {
            Return(0x01)
        }
    }

}
