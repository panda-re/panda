import os
import sys
import time
import json
import tarfile
import traceback
import argparse
import itertools
import tempfile
import hashlib
from io import StringIO

SUFFIX_MAPPER = {
    '-rr-nondet.log' : 'nondetlog',
    '-rr-snp'        : 'snapshot',
    '-rr.cmd'        : 'capture.cmd'
}

def fixup_basename(basename):
    potential_endings = itertools.chain(SUFFIX_MAPPER.keys(), ['-rr'])
    for ending in potential_endings:
        if basename.endswith(ending):
            basename = basename.replace(ending, '')
            break

    for required_ending in SUFFIX_MAPPER.keys():
        fpath = basename + required_ending
        if not os.path.isfile(fpath):
            raise IOError("Could not find required RR file {}".format(fpath))
    return basename

def validate_args(args):
    args.basename = fixup_basename(args.basename)
    if not args.output:
        args.output = os.path.basename(args.basename) + '.rr2'
    if os.path.exists(args.output):
        if not os.path.isfile(args.output):
            raise IOError("Output must be a file path, not a directory")
        if not args.force:
            raise IOError("Output file already exists. Please remove or use --force")
        os.unlink(args.output)
    if args.metadata:
        if not os.path.isfile(args.metadata):
            raise IOError("Cannot read {}".format(args.metadata))
        with open(args.metadata, 'r') as fobj:
            json.load(fobj)
    return args

def dbg_print(args, string):
    if args.verbose:
        print(string)

def add_rrmagic(tfile):
    with tempfile.NamedTemporaryFile(mode = "w") as fobj:
        fobj.write("Packed at {}".format(time.ctime()))
        fobj.flush()
        tfile.add(fobj.name, "RRv2", recursive=False)

def calculate_hashes(tfile, args):
    hashes = {}
    for member in tfile.getmembers():
        filename = member.name
        sha1 = hashlib.sha1()
        inobj = tfile.extractfile(member)
        data = inobj.read(4096)
        while data:
            sha1.update(data)
            data = inobj.read(4096)
        digest = sha1.hexdigest()
        hashes[filename] = digest
    return hashes

def add_hashes(args):
    hashes = {}
    with tarfile.open(name=args.output, mode='r') as tfile:
        hashes = calculate_hashes(tfile, args)
    with tarfile.open(name=args.output, mode='a:') as tfile:
        with tempfile.NamedTemporaryFile(mode = "w") as tempobj:
            for filename, digest in sorted(hashes.items()):
                dbg_print(args, "...{}: {}".format(filename, digest))
                tempobj.write("{}: {}\n".format(filename, digest))
            tempobj.flush()
            tfile.add(tempobj.name, 'sha1')

def add_files(tfile, args):
    for required_ending, arcname in sorted(SUFFIX_MAPPER.items()):
        dbg_print(args, "...adding {}".format(arcname))
        fpath = args.basename + required_ending
        tfile.add(fpath, arcname=arcname, recursive=False)

def add_metadata(tfile, args):
    if not args.metadata:
        with tempfile.NamedTemporaryFile(mode = "w") as tempobj:
            json.dump({}, tempobj)
            tempobj.flush()
            tfile.add(tempobj.name, 'metadata.json')
    else:
        tfile.add(args.metadata, 'metadata.json', recursive=False)

def create_rr2(args):
    print("Packing {} into {}".format(args.basename, args.output))

    with tarfile.open(name=args.output, mode='w:') as tfile:
        dbg_print(args, "Adding RRv2 magic file")
        add_rrmagic(tfile)
        dbg_print(args, "Adding replay files")
        add_files(tfile, args)
        dbg_print(args, "Adding metadata")
        add_metadata(tfile, args)
    dbg_print(args, "Adding file hashes")
    add_hashes(args)

def main():
    parser = argparse.ArgumentParser("Pack output from PANDA recording into an .rr2")
    parser.add_argument("basename", type=str,
                            help="Path to one of the recording files (or common prefix)")
    parser.add_argument("--metadata", type=str, help="An optional JSON file of metadata")
    parser.add_argument("--output", type=str,
                            help="Path for the new .rr2 (default basename.rr2)")
    parser.add_argument("--force", action="store_true",
                            help="Overwrite --output if it exists")
    parser.add_argument("--verbose", action="store_true",
                            help="Print extra information messages")
    args = parser.parse_args()
    try:
        args = validate_args(args)
    except:
        traceback.print_exc()
        print ("\n\n[ERROR]: Failed to validate arguments, exiting...")
        sys.exit(1)

    try:
        create_rr2(args)
    except:
        traceback.print_exc()
        print("Failed to pack {}".format(args.basename))
        if os.path.exists(args.output):
            os.unlink(args.output)
        sys.exit(2)

if __name__ == '__main__':
    main()
