import subprocess
import re

subprocess.call("llvm-dis-3.3 llvm-mod.bc", shell=True)
f = open("llvm-mod.ll", "r").readlines()
# f = [line for line in f if re.search("zext.*to i64",line) is None ]
# f = [line for line in f if re.search("(bitcast|zext).*to i8",line) is None ]
f = [line for line in f if re.search("taint",line) is None ]

open("llvm-mod.ll", "w").write("".join(f))
