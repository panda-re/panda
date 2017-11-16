#!/usr/bin/python

import os
import subprocess as sp
import sys
import re
import shutil 

thisdir = os.path.dirname(os.path.realpath(__file__))
td = os.path.realpath(thisdir + "/../..")
sys.path.append(td)

from ptest_utils import *

record_debian("guest:/bin/cat guest:/etc/passwd", "cat", "i386")

ss_filename = miscdir + "/cat_search_strings.txt"
ssf = open(ss_filename, "w")
ssf.write("Debian User\n")
ssf.close()
