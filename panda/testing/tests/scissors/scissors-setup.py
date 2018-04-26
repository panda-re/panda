#!/usr/bin/python

import os
import sys
import subprocess as sp

thisdir = os.path.dirname(os.path.realpath(__file__))
td = os.path.realpath(thisdir + "/../..")
sys.path.append(td)

from ptest_utils import *

record_debian("find /usr/bin", "find", "i386") 
record_debian("netstat -a", "netstat", "i386") 


