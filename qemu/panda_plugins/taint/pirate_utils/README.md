pirate_utils
========

These tools provide support for tainting, and querying taint on files.
Currently, Windows x86 32/64 bit are supported, as well as Linux (or any
platform with gcc) for x86, x86_64, and ARM.  Linux tools can be compiled with
the Makefile, and Windows binaries are in `pirate_utils/windows/Release`.

pirate_label
------------

    pirate_label <file> <label> <start_offset> <region_size> <chunk_size>
    This utility enables labeling every byte of <file> with configurable labels.
        <file> = full path to file to be labeled
        <label> = label as an int
        <start_offset> = start labeling at given offset
        <region_size> = length of region to label (-1 = whole file)
        <chunk_size> = label the file in chunks (i.e. labels are chunked for each <chunk_size> bytes)
            NB: chunk_size must be <= 4096 bytes (and, of course, <= <region_size>).
            NB: chunk_size = -1 means no splitting (single label of <label>).

pirate_query
------------

    pirate_query <file> <start_offset> <end_offset>
    This utility enables querying taint on bytes in <file>.
        <file> = full path to file to be labeled
        <start_offset> = beginning of region to be queried (in bytes)
        <len> = number of bytes to be queried or -1 for 'end-of-file'

Examples
-----

`pirate_query` is pretty straightforward, but here are a few examples of using
`pirate_label` for common file labeling schemes:

* Label each byte in the file with a positional label (label parameter is
  ignored)

    `./pirate_label <file> 0 0 -1 1`

* Apply a single label of 1 to each byte in the file

    `./pirate_label <file> 1 0 -1 -1`

* Apply labels at a granularity of 1KB to the file.  With this option, each
  chunk is labeled with the start offset of the chunk.  So for a 2KB file, the
  first KB will have label 0, and the second KB will have a label of 1024 (label
  parameter is ignored).

    `./pirate_label <file> 0 0 -1 1024`

