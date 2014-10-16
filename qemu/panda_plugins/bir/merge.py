
from parcor import *

#
#  This is known to run on a 24-core, 128GB RAM VM
#


import os
import re
import magic


indexable = [
    "COM executable for DOS",
    "DOS executable (COM)",
    "GLF_BINARY_MSB_FIRST",
    "GLS_BINARY_LSB_FIRST",
    "Hitachi SH big-endian COFF object, not stripped",
    "MS-DOS executable, NE for MS Windows 3.x",
    "PE32 executable (console) Intel 80386, for MS Windows",
    "PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows",
    "PE32+ executable (console) x86-64, for MS Windows",
    "PE32+ executable (console) x86-64 Mono/.Net assembly, for MS Windows",
    "PE32 executable (DLL) (console) Intel 80386, for MS Windows",
    "PE32 executable (DLL) (console) Intel 80386 Mono/.Net assembly, for MS Windows",
    "PE32+ executable (DLL) (console) x86-64, for MS Windows",
    "PE32+ executable (DLL) (console) x86-64 Mono/.Net assembly, for MS Windows",
    "PE32+ executable (DLL) (EFI application) x86-64, for MS Windows",
    "PE32 executable (DLL) (GUI) Intel 80386, for MS Windows",
    "PE32 executable (DLL) (GUI) Intel 80386 Mono/.Net assembly, for MS Windows",
    "PE32 executable (DLL) (GUI) Intel 80386 (stripped to external PDB), for MS Windows",
    "PE32+ executable (DLL) (GUI) x86-64, for MS Windows",
    "PE32+ executable (DLL) (GUI) x86-64 Mono/.Net assembly, for MS Windows",
    "PE32 executable (DLL) (native) Intel 80386, for MS Windows",
    "PE32+ executable (DLL) (native) x86-64, for MS Windows",
    "PE32 executable (GUI) Intel 80386, for MS Windows",
    "PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows",
    "PE32+ executable (GUI) x86-64, for MS Windows",
    "PE32+ executable (GUI) x86-64 Mono/.Net assembly, for MS Windows",
    "PE32 executable (native) Intel 80386, for MS Windows",
    "PE32+ executable (native) x86-64, for MS Windows",
    "PE32 executable (Unknown subsystem 0x10) Intel 80386, for MS Windows",
    "PE32+ executable (Unknown subsystem 0x10) x86-64, for MS Windows",
    "8086 relocatable (Microsoft)",
    "current ar archive",
    "^data$", 
    "Debian binary package (format 2.0)",
    "ELF 32-bit LSB executable",
    "ELF 32-bit LSB relocatable",
    "ELF 32-bit LSB shared object", 
    "ELF 64-bit LSB relocatable",
    "ELF 64-bit",
    "GNU dbm 1.x or ndbm little endian",
    "Hitachi SH big-endian COFF object, stripped",
    "Linux kernel x86 boot executable ",
    "magic binary file ",
    "very short file"]


def cmd(cmd_str, output, timeit):
    if timeit:
        print "cmd = [%s]" % cmd_str
        t1 = time.time()
    p = subprocess.Popen(cmd_str.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE) 
    res = p.communicate()  
    if timeit:
        t2 = time.time()
        print "%.2f sec\n" % (t2-t1)  
    if output:
        return res

rebuild_file_list = False

files = []
#file_types = set([])
if rebuild_file_list:
    files = []
    c = {}
    i=0
    for filename in open("./deb7-64bit-filelist"):
        i += 1
        if ((i%100) == 0):
            print "i=%d" % i
        foo = re.search("(.*)\s*$", filename)
        if foo:
            filename = foo.groups()[0]
        with magic.Magic() as m:
            ft = m.id_filename(filename)
            if not (ft in c):
                c[ft] = 0
            c[ft] += 1
            if ft in indexable:
                files.append(filename)
    for ft in sorted(c.keys()):
        print "%6d %s" % (c[ft], ft)
    print "%d files to index" % (len(files))
    f = open("./filelist-binonly", "w")
    for filename in files:
        f.write(filename + "\n")
    f.close()
    print "created binary-only file list"
    die 

files = []
for filename in open("./filelist-binonly"):                                                                                                              
        files.append(filename) 

#    foo = re.search("ntos", filename)
#    if foo:
#        files.append(filename)
#    foo = re.search(".dll$", filename)
#    if foo:
#        files.append(filename)
#    foo = re.search(".exe$", filename)
#    if foo:
#        files.append(filename)
    
#    foo = re.search("home", filename)
#    if foo:
#        continue
#    foo = re.search("debug", filename)
#    if foo:
#        continue
#    foo = re.search("/opt/", filename)
#    if foo:
#        continue


print "%d files to index" % (len(files))


#for filen in files:
#    print filen,



# chunk size (we will index this many files at a time                                                                                        
cs = 20
# min, max ngrams                                                                                                                            
min_n = 1
max_n = 3
# passage len                                                                                                                                
passage_len = 512
    
bin_dir = os.getcwd()
ind_dir = "/data/laredo/tleek/bir/deb7-64"
ind_fn = "%s/ind" % ind_dir
chunk_pfx = "%s/chunk" % ind_dir
ind_tmp_fn = "%s/ind_tmp" % ind_dir
    

class IndexJob(Job):
    def __init__(self, bin_dir, ind_dir, chunk, filelist, min_n, max_n, passage_len):
        self.ind_dir = ind_dir
        # this is an integer
        self.chunk = chunk
        self.filelist = filelist
        self.min_n = min_n
        self.max_n = max_n
        self.passage_len = passage_len
        self.level = 1
        chunk_name = "index-%d" % chunk
        chunk_pfx = "%s/%s" % (ind_dir, chunk_name)
        cmd_str = "%s/bi %s %s %d %d %d" % (bin_dir, filelist, chunk_pfx, min_n, max_n, passage_len)
        self.mem_required = 15000000
        super(IndexJob, self).__init__(chunk_name, cmd_str)


num_merges = 0
        
class MergeJob(Job):

    def __init__(self, bin_dir, ind_dir, chunk1_name, chunk2_name, level):
        self.ind_dir = ind_dir
        self.chunk1_name = chunk1_name
        self.chunk2_name = chunk2_name
        self.level = level
        chunk1_pfx = "%s/%s" % (ind_dir, chunk1_name)
        chunk2_pfx = "%s/%s" % (ind_dir, chunk2_name)
#        merge_name = "merge-%s-%s" % (chunk1_name, chunk2_name)
        global num_merges
        merge_name = "merge-l%d-n%d" % (self.level, num_merges)
        print "Creating merge job %s: %s %s" % (merge_name, chunk1_name, chunk2_name)
        num_merges += 1
        merge_pfx = "%s/%s" % (ind_dir, merge_name)
        cmd_str = "%s/bm %s %s %s" % (bin_dir, chunk1_pfx, chunk2_pfx, merge_pfx)
        self.mem_required = 15000000
        super(MergeJob, self).__init__(merge_name, cmd_str)
        


class MergeJobSet (JobSet):

    def __init__(self, name):
        # gated by memory
        self.max_jobs = 7
        super(MergeJobSet, self).__init__(name)

    def create_new(self):
        # consider all pairs of jobs in the finished set.  
        # Keep all pairs that are both IndexJobs
        # Now, if any of these pairs have same level,
        # create a merge job
        for j1 in self.finished:
            for j2 in self.finished:
                if j1 == j2:
                    continue
                if j1.level == j2.level:
                    mj = MergeJob(bin_dir, ind_dir, j1.name, j2.name, 1 + j1.level)
                    return (mj, set([j1, j2]))
        # try again, this time dont require levels match
        for j1 in self.finished:
            for j2 in self.finished:
                if j1 == j2:
                    continue
                mj = MergeJob(bin_dir, ind_dir, j1.name, j2.name, 1 + max(j1.level, j2.level))
                return (mj, set([j1, j2]))
        return super(MergeJobSet, self).create_new()

        

print "%d chunks of size %d\n" % (1 + (len(files)) / cs, cs)

pcjs = MergeJobSet("merge")

start = 0
chunk = 0
while (start < len(files)):
    print "\n===================================================================\n"
    print "\nChunk %d\n" % chunk
    # create a file list file for chunk
    # containing files[start:start+cs]
    filelist = "/tmp/f%d" % chunk
    print "writing %s" % filelist
    f = open(filelist, "w")
    print "  files %d" % start,
    p = 0
    for i in range(cs):
        p = start + i
        if p<len(files):
            f.write(files[p])
        else:
            break
    f.close()
    print " .. %d" % p
    # add indexing chunks to waiting list
    chunk_name = "ind-%d" % chunk
    chunk_pfx = "%s/chunk-%d" % (ind_dir, chunk)
    cmd_str = "%s/bi %s %s %d %d %d" % (bin_dir, filelist, chunk_pfx, min_n, max_n, passage_len)
    job = IndexJob(bin_dir, ind_dir, chunk, filelist, min_n, max_n, passage_len)
    pcjs.waiting.add(job)
    chunk +=1 
    start += cs

random.seed()

# run parcor, merging
pcjs.run()
