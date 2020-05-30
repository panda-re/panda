#!/usr/bin/env python3
#
# rrtool.py - Convert old-style multi-file PANDA traces to the new-style
# RRArchive format. See panda/docs/RRArchive.md  for details on the format.
# The script has been tested with Python 3.6. Older Python 3 releases should
# also work, after minor tweaks.
#
# Author:
#   Manolis Stamatogiannakis <manolis.stamatogiannakis@vu.nl>
#
# This work is licensed under the terms of the GNU GPL, version 2.
# See the COPYING file in the top-level directory.
#

import argparse
import collections
import concurrent.futures
import hashlib
import io
import json
import logging
import os
import re
import struct
import tarfile
import threading
from pathlib import Path

logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.INFO)

class RRArchive:
    """
    Class representing an RRArchive.
    """
    version = 1
    extmap = {
        '': '.tar',
        'gz': '.tar.gz',
    }
    checksum_workers = 4
    checksum_algo = 'sha256'
    checksum_block = 64*1024
    metadata_schema = 'rrmeta:1'
    metadata_indent = 2

    def __init__(self, ndfilename, opts):
        """
        Construct an RRArchive. Currently the input can only be an old-style
        trace file.

        :param ndfilename: Filename of the nondet log to convert.
            Other filenames will be derived from it.
        :param opts: A dict-like object containing options.
            This is more convenient from specifying a concrete interface for
            all methods used.
        :raises RuntimeError: One of the expected input files doesn't exist.
        :raises ValueError: One of the expected input files is not in the 
            expected format.
        """
        # check ndfile
        self.ndfile = Path(ndfilename)
        if not self.ndfile.is_file():
            logging.error("Nondet file %r does not exist.", self.ndfile)
            raise RuntimeError("Nondet file %r does not exist." % (self.ndfile))
        # set rrdir / rrbase
        self.rrdir = self.ndfile.parent
        ndname_re = opts.nondet_fmt.replace('{rrbase}', '(?P<rrbase>.*)', 1)
        ndname_match = re.match(ndname_re, self.ndfile.name)
        if not ndname_match:
            logging.error("Nondet file %r does not match with regex %r.", self.ndfile, ndname_re)
            raise ValueError("Nondet file %r does not match with regex %r." % (self.ndfile, ndname_re))
        else:
            self.rrbase = ndname_match.group('rrbase')
        # check snpfile
        self.snpfile = self.rrdir / opts.snp_fmt.format(rrbase=self.rrbase)
        if not self.snpfile.is_file():
            logging.error("Snapshot file %r does not exist.", self.snpfile)
            raise RuntimeError("Snapshot file %r does not exist." % (self.snpfile))
        # check cmdfile
        self.cmdfile = self.rrdir / opts.cmd_fmt.format(rrbase=self.rrbase)
        if not self.snpfile.is_file():
            logging.warning("Command file %r does not exist.", self.cmdfile)
            self.cmdfile = None

        # create contents description for archive
        self.contents = collections.OrderedDict()
        self.contents['PANDArr'] = self._helper_magic
        self.contents['rr-snp'] = self.snpfile
        self.contents['rr-nodet.log'] = self.ndfile
        self.contents['metadata.json'] = self._helper_metadata

        # copy stuff from opts
        self.dummy = opts.dummy
        self.fix_timestamps = opts.fix_timestamps

        # initialize other variables to None
        self.archive = None
        self.file_checksums_tpe = None

    def write_item(self, item, name):
        """
        Write an item to the archive. The archive must be already open.

        :param item: Item to write. May be a Path, string or callable.
        :param name: The archive name to use for the item. The item will still
            be stored under the rrbased directory in the archive.
        :raises RuntimeError: The archive hasn't been opened yet.
        :raises ValueError: The type of the added item is not supported.
        :returns: A tuple with the name of the item in the archive and
            a character signifying the type of the added item.
        """
        if self.archive is None:
            raise RuntimeError("No archive is currently open for %r." % (self))
        arcname = Path(self.rrbase) / name

        if isinstance(item, Path):
            if not self.dummy:
                self.archive.add(item, arcname=arcname)
            else:
                self.write_item('DUMMY', name)
            return (arcname, 'f')

        item_type = None
        if callable(item):
            item = item(name)
            item_type = 'c'
        if isinstance(item, str):
            # base tarinfo on ndfile - override only name/size
            tarinfo = self.archive.gettarinfo(name=self.ndfile, arcname=arcname)
            contents = io.BytesIO()
            contents.write(item.encode('utf-8'))
            if item[-1] != '\n':
                contents.write('\n'.encode('utf-8'))
            tarinfo.size = contents.tell()
            contents.seek(0)
            self.archive.addfile(tarinfo=tarinfo, fileobj=contents)
            item_type = 's' if item_type is None else item_type
        if item_type is None:
            raise ValueError("Unsupported item type for entry %s.", name)
        return (arcname, item_type)

    def write(self, arcbase=None, arcmode='w:gz'):
        if self.archive is not None:
            raise RuntimeError("Archive already open for %r." % (self))

        compression = arcmode.rsplit(':', 1)[-1]
        if compression in self.__class__.extmap:
            ext = self.__class__.extmap[compression]
        else:
            logging.error("Unsupported tarfile mode: %r", arcmode)
            raise ValueError("Unsupported tarfile mode: %r" % (arcmode))
        if arcbase is None:
            arcname = self.rrdir / (self.rrbase + ext)
        else:
            arcname = self.rrdir / (arcbase + ext)

        # start checksumming concurrently with the archive creation
        self._make_file_checksums([(item, name) for name, item
            in self.contents.items() if isinstance(item, Path)])
        # write contents
        logging.info("Creating rr archive %s...", arcname)
        self.archive = tarfile.open(name=arcname, mode=arcmode)
        for name, item in self.contents.items():
            item_name, item_type = self.write_item(item, name)
            logging.info("\t|-[%s] %s", item_type, item_name)
        self.archive.close()
        self.archive = None
        # set timestamp
        if self.fix_timestamps:
            logging.info("Fixing archive timestamps.")
            ts = (os.path.getatime(self.ndfile), os.path.getmtime(self.ndfile))
            print(arcname)
            os.utime(arcname, ts)
        # done
        logging.info("Finished writing rr archive %s.\n", arcname)

    def _helper_magic(self, name):
        """
        Helper for creating the contents of the magic filename in the archive.
        """
        mfmt = 'PANDArr:version={version}:basename={basename}'
        mctx = {'version': self.version, 'basename': self.rrbase}
        return mfmt.format(**mctx)

    def _helper_metadata(self, name):
        """
        Helper for creating the contents of the magic filename in the archive.
        """
        metadata = {
            'schema': self.__class__.metadata_schema,
            'checksums': {},
            'cmd': self.cmdfile.read_text(encoding='utf-8') if self.cmdfile else None,
            'instructions': self._get_nd_instructions(),
        }
        logging.info("Waiting for checksums to complete...")
        for future in concurrent.futures.as_completed(self.file_checksums):
            metadata['checksums'].update(dict( (future.result(), ) ))
        self.file_checksums_tpe.shutdown()
        self.file_checksums_tpe = None
        self.file_checksums = None
        return json.dumps(metadata, sort_keys=True, indent=self.__class__.metadata_indent)

    def _get_nd_instructions(self):
        with self.ndfile.open('rb') as nd:
            nd.seek(16)
            return struct.unpack('<Q', nd.read(8))[0]

    def _make_file_checksums(self, items):
        """
        Calculate the checksum of multiple files concurrently in the background.
        Results will be available through self.file_checksums.
        """

        def _file_checksum(filename, filename_id=None):
            """
            Calculate the checksum of a single file.
            """
            hasher = getattr(hashlib, self.__class__.checksum_algo, None)
            if hasher is None:
                raise ValueError("Can't find algorithm %r in hashlib." % (self.__class__.checksum_algo))
            logging.info("Calculating %s hash for %r.", self.__class__.checksum_algo, filename)
            hasher = hasher()
            with filename.open('rb') as f:
                block = f.read(self.__class__.checksum_block)
                while block:
                    hasher.update(block)
                    block = f.read(self.__class__.checksum_block)
            if filename_id is None:
                filename_id = filename
            return (filename_id, '%s:%s' % (self.__class__.checksum_algo, hasher.hexdigest()))

        if self.file_checksums_tpe is not None:
            raise RuntimeError("Checksum executor already exists for %r." % (self))
        nw = min(self.__class__.checksum_workers, len(items))
        files = [it[0] for it in items]
        logging.info("Started calculating checksums for %s using %d workers.", files, nw)
        # see: https://realpython.com/intro-to-python-threading/
        self.file_checksums_tpe = concurrent.futures.ThreadPoolExecutor(max_workers=nw)
        self.file_checksums = [self.file_checksums_tpe.submit(_file_checksum, f, n) for f, n in items]

    def __str__(self):
        cfmt = lambda it: '%s()' % it.__name__ if callable(it) else it
        return str(['%s:%s' % (k, cfmt(v)) for k, v in self.contents.items()])

    def __repr__(self):
        return '%s<%s/%s>' % (self.__class__.__name__, self.rrdir, self.rrbase)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='PANDA trace converter.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('--nondet-fmt', default='{rrbase}-rr-nondet.log',
        help='Filename format for non-determinism log files.')
    parser.add_argument('--snp-fmt', default='{rrbase}-rr-snp',
        help='Filename format for command initial memory snapshot files.')
    parser.add_argument('--cmd-fmt', default='{rrbase}.cmd',
        help='Filename format for command line fileis.')
    parser.add_argument('-T', '--fix-timestamps', action='store_true',
        help='Fix the timestamps of the output archive to match '
             'the timestamps of the non-determinism log.')
    parser.add_argument('--dummy', action='store_true',
        help='Write dummy files instead of the non-determinism and '
             'snapshot files. Makes debugging metadata handling faster.')
     #parser.add_argument('--delete', action='store_true',
        #help='Remove traces after conversion.')
    parser.add_argument('ndfiles', metavar='NONDET-FILE', nargs='+')
    opts = parser.parse_args()

    for ndf in opts.ndfiles:
        ar = RRArchive(ndf, opts)
        ar.write()

