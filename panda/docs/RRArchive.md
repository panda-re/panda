# The RRArchive Format

## Background
Traditionally, a PANDA trace comprises of two files: The initial memory
snapshot (`trace-rr-snp`) and a log file containing the non-deterministic
inputs usesd (`trace-rr-nondet.log`). Additionally, a good practice is to
add a third file, containing the command line used to produce a trace.

As the main log files are very bulky, an early attempt to reduce their
size and make sharing easier was the `rrpack.py` script. The script packed
the log files in a custom `trace.rr` file that contained a rudimentary
header, followed by the data of a [xz][xz]-compressed tarball with the
trace files.

However, `rrpack.py` was mostly meant as an intermediate format, used
for convenient storage and transmission. PANDA itself is not able to
read `.rr` files. The RRArchive format comes to fill this gap.
I.e. define a format that is both easy to handle, and can be directly
used by PANDA.

## Specification of the RRArchive format
RRArchive format aims for simplicity and flexibility. For this, the
following high-level choices were made:

* RRArchive files are simple compressed tarballs. No special suffix
  is used.
* Initially, only [gzip][gzip] compression is supported.
  Later, support for other compressions can be added, as long as they
  are supported by [libarchive][libarchive].
* All the files must be contained inside a single directory, named
  same as the trace. We call that the *basename* of the trace.

Regarding the contents of an RRArchive, it was decided to keep the
requirement as flexible as possible. Specifically, the only required
files are:

* Magic file `<basename>/PANDArr`: This file is retrieved by order,
  so it must come first in the archive. This allows tools to abort
  as early as possible if the file contents are not valid. Moreover,
  it contains the basename of the trace, so that the remaining files
  in the RRArchive can be retrieved by name.
  It must contain a single line in the following format:
  `PANDArr:version={version}:basename={basename}`
* Snapshot file `<basename>/rr-snp`: This is the initial memory
  snapshot file. It is recommended that it comes right after the magic
  file. libarchive should be able to find it in another position, but
  that would probably be slower.
* Non-determinism log file `<basename>/rr-snp`: The actual execution
  trace.
* Metadata file `<basename>/metadata.json`: This file contains any
  additional metadata related to the trace in JSON format.
  The metadata are provided for convenience only. PANDA is able to
  process the trace even if the file is empty.
  See XXX for a recommended set of metadata to be included in the file.
  
## Implementation status
The implementation of RRArchive has two high-level components:
* An utility for manipulating RRArchive implemented in Python.
* Support for the archives in PANDA is implemented using 
  [libarchive][libarchive].

+++

[xz]: https://en.wikipedia.org/wiki/XZ_Utils
[gzip]: https://en.wikipedia.org/wiki/Gzip
[libarchive]: https://libarchive.org/

