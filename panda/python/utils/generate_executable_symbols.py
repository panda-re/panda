import argparse
import subprocess
import yaml
from os import walk, path
from os.path import isfile

parser = argparse.ArgumentParser(
    description='Pull symbols out of guest file system for all executables.')
parser.add_argument(
    '--fspath', help="path to the guest file system", required=True)
parser.add_argument('--out', help="path to the output file",
                    required=True, type=argparse.FileType('w'))

args = parser.parse_args()


class HexInt(int):
    pass


def representer(dumper, data):
    return yaml.ScalarNode('tag:yaml.org,2002:int', hex(data))


yaml.add_representer(HexInt, representer)

files = [path.join(r, f) for r, d, f in walk(args.fspath) for f in f]
elfsymbolmappings = {}
for f in files:
    if isfile(f):
        with open(f, "rb") as fo:
            if fo.read(4) == b"\x7fELF":
                result = subprocess.run(
                    ['nm', '-D', f], stdout=subprocess.PIPE)
                if b"no symbols" in result.stdout:
                    continue
                symbolmapping = {}
                for line in result.stdout.split(b"\n"):
                    elements = line.split()
                    if len(elements) == 3:
                        symbolmapping[elements[2].decode()] = HexInt(
                            int(elements[0], 16))  # why? standardizes output
                foutname = f[1:]  # "./bin/bash" -> "/bin/bash"
                elfsymbolmappings[foutname] = symbolmapping

args.out.write(yaml.dump(elfsymbolmappings))
