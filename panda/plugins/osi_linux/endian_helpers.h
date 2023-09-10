// OSI Linux works with a bunch of pointers which we need to
// flip if the guest/host endianness mismatch.
//
#pragma once

static inline void fixupendian_impl(void* px, size_t size) {
    if (size == 4) {
        *(uint32_t*)px = bswap32(*(uint32_t*)px);
    } else if (size == 8) {
        *(uint64_t*)px = bswap64(*(uint64_t*)px);
    }
}

#if defined(TARGET_WORDS_BIGENDIAN) != defined(HOST_WORDS_BIGENDIAN)
// If guest and host endianness don't match:
// fixupendian will flip a dword in place
#define fixupendian(x)         {x=bswap32((target_ptr_t)x);}
#define fixupendian64(x)       {x=bswap64((uint64_t)x);}
// of flipbadendian will flip a dword
#if TARGET_LONG_BITS == 64
#define flipbadendian(x)       bswap64((target_ptr_t)x)
#else
#define flipbadendian(x)       bswap32((target_ptr_t)x)
#endif

#define flipbadendian64(x)     bswap64((uint64_t)x)
#define fixupendian2(x) fixupendian_impl(&(x), sizeof(x))
#else
#define fixupendian(x)         {}
#define fixupendian64(x)       {}
#define flipbadendian(x)       x
#define flipbadendian64(x)     x

#define fixupendian2(x)         {}
#endif

