// Storage for boot definitions.
#ifndef __BOOT_H
#define __BOOT_H

// boot.c
void boot_setup(void);
void boot_add_bev(u16 seg, u16 bev, u16 desc, int prio);
void boot_add_bcv(u16 seg, u16 ip, u16 desc, int prio);
struct drive_s;
void boot_add_floppy(struct drive_s *drive_g, const char *desc, int prio);
void boot_add_hd(struct drive_s *drive_g, const char *desc, int prio);
void boot_add_cd(struct drive_s *drive_g, const char *desc, int prio);
void boot_add_cbfs(void *data, const char *desc, int prio);
void boot_prep(void);
struct pci_device;
int bootprio_find_pci_device(struct pci_device *pci);
int bootprio_find_ata_device(struct pci_device *pci, int chanid, int slave);
int bootprio_find_fdc_device(struct pci_device *pci, int port, int fdid);
int bootprio_find_pci_rom(struct pci_device *pci, int instance);
int bootprio_find_named_rom(const char *name, int instance);
int bootprio_find_usb(struct pci_device *pci, u64 path);

#endif // __BOOT_H
