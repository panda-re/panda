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

passphrase = '"tygertygerburningbright"'
record_32bitlinux("guest:/usr/bin/ssh-keygen -t rsa -N " + passphrase + " -f foo", "ssh-keygen")

create_search_string_file(passphrase)

