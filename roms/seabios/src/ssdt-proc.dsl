/* This file is the basis for the ssdt_proc[] variable in src/acpi.c.
 * It defines the contents of the per-cpu Processor() object.  At
 * runtime, a dynamically generated SSDT will contain one copy of this
 * AML snippet for every possible cpu in the system.  The objects will
 * be placed in the \_SB_ namespace.
 *
 * To generate a new ssdt_proc[], run the commands:
 *   cpp -P src/ssdt-proc.dsl > out/ssdt-proc.dsl.i
 *   iasl -ta -p out/ssdt-proc out/ssdt-proc.dsl.i
 *   tail -c +37 < out/ssdt-proc.aml | hexdump -e '"    " 8/1 "0x%02x," "\n"'
 * and then cut-and-paste the output into the src/acpi.c ssdt_proc[]
 * array.
 *
 * In addition to the aml code generated from this file, the
 * src/acpi.c file creates a NTFY method with an entry for each cpu:
 *     Method(NTFY, 2) {
 *         If (LEqual(Arg0, 0x00)) { Notify(CP00, Arg1) }
 *         If (LEqual(Arg0, 0x01)) { Notify(CP01, Arg1) }
 *         ...
 *     }
 * and a CPON array with the list of active and inactive cpus:
 *     Name(CPON, Package() { One, One, ..., Zero, Zero, ... })
 */
DefinitionBlock ("ssdt-proc.aml", "SSDT", 0x01, "BXPC", "BXSSDT", 0x1)
/*  v------------------ DO NOT EDIT ------------------v */
{
    Processor (CPAA, 0xAA, 0x0000b010, 0x06) {
        Name (ID, 0xAA)
/*  ^------------------ DO NOT EDIT ------------------^
 *
 * The src/acpi.c code requires the above layout so that it can update
 * CPAA and 0xAA with the appropriate CPU id (see
 * SD_OFFSET_CPUHEX/CPUID1/CPUID2).  Don't change the above without
 * also updating the C code.
 */
        Name (_HID, "ACPI0007")
        External(CPMA, MethodObj)
        External(CPST, MethodObj)
        External(CPEJ, MethodObj)
        Method(_MAT, 0) {
            Return(CPMA(ID))
        }
        Method (_STA, 0) {
            Return(CPST(ID))
        }
        Method (_EJ0, 1, NotSerialized) {
            CPEJ(ID, Arg0)
        }
    }
}
