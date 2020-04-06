import ctypes

# x86, x86-64, ARM, AArch 64
IOC_TYPE_BITS = 8
IOC_CMD_BITS  = 8
IOC_SIZE_BITS = 14
IOC_DIR_BITS  = 2

# PPC overwrite
TARGET_PPC = False
if TARGET_PPC:
    IOC_SIZE_BITS = 13
    IOC_DIR_BITS  = 3

class IoctlCmdBits(ctypes.LitteEndianStructure):
    __fields__ = [
        ("direction", ctypes.c_uint8, IOC_DIR_BITS),
        ("arg_size", ctypes.c_uint16, IOC_SIZE_BITS),
        ("cmd_num", ctypes.c_uint8, IOC_CMD_BITS),
        ("type_num", ctypes.c_uint8, IOC_TYPE_BITS)
    ]

class IoctlCmd(ctypes.Union):
    __fields__ = [
        ("bits", IoctlCmdBits),
        ("asUnsigned32", ctypes.c_uint32)
    ]

    def __str__(self):

        if self.bits.direction == 0x0:
            direction = "IO"
        elif self.bits.direction == 0x1:
            direction = "IOW"
        elif self.bits.direction == 0x2:
            direction = "IOR"
        elif self.bits.direction == 0x3:
            direction = "IOWR"
        else:
            raise RuntimeError("Invalid ioctl direction decode!")

        return "dir={},arg_size={:x},cmd={:x},type={:x}".format(
            direction,
            self.bits.arg_size,
            self.bits.cmd_num,
            self.bits.type
        )

class Ioctl(object):

    '''
    Unpacked ioctl command with optional buffer
    '''

    def __init__(self, panda, cpu, cmd, guest_ptr):

        self.cmd = IoctlCmd()
        self.cmd.asUnsigned32 = cmd
        if (self.cmd.bits.arg_size > 0):
            try:
                self.guest_ptr = guest_ptr
                self.guest_buf = panda.virtual_memory_read(cpu, self.guest_ptr, self.cmd.bits.arg_size)
            except ValueError:
                raise RuntimeError("Failed to read guest ioctl buffer!")
        else:
            self.guest_ptr = None
            self.guest_buf = None

    def __str__(self):

        if (self.guest_ptr == None):
            return "ioctl({})".format(str(self.cmd))
        else:
            return "ioctl({},ptr={:08x},buf={}".format(
                str(self.cmd),
                self.guest_ptr,
                self.guest_buf
            )
