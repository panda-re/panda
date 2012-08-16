# Code size reduction.
#
CFLAGS		+= -fstrength-reduce -fomit-frame-pointer

# Code size reduction.  gcc3 needs a different syntax to gcc2 if you
# want to avoid spurious warnings.
#
CFLAGS		+= -falign-jumps=1 -falign-loops=1 -falign-functions=1

# Use %rip-relative addressing wherever possible.
#
CFLAGS		+= -fpie

# Force 64-bit code
#
CFLAGS		+= -m64
ASFLAGS		+= --64
LDFLAGS		+= -m elf_x86_64

# EFI requires -fshort-wchar, and nothing else currently uses wchar_t
#
CFLAGS		+= -fshort-wchar

# We need to undefine the default macro "i386" when compiling .S
# files, otherwise ".arch i386" translates to ".arch 1"...
#
CFLAGS			+= -Ui386

# x86_64-specific directories containing source files
#
SRCDIRS		+= arch/x86_64/prefix

# Include common x86 Makefile
#
MAKEDEPS	+= arch/x86/Makefile
include arch/x86/Makefile

# Include platform-specific Makefile
#
MAKEDEPS	+= arch/x86_64/Makefile.$(PLATFORM)
include arch/x86_64/Makefile.$(PLATFORM)
