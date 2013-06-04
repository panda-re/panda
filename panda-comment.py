import re


PBC = "PANDABEGINCOMMENT"
PEC = "PANDAENDCOMMENT"

repltxt =  " * \n"
repltxt +=  " * Authors:\n"
repltxt +=  " *  Tim Leek               tleek@ll.mit.edu\n"
repltxt +=  " *  Ryan Whelan            rwhelan@ll.mit.edu\n"
repltxt +=  " *  Joshua Hodosh          josh.hodosh@ll.mit.edu\n"
repltxt +=  " *  Michael Zhivich        mzhivich@ll.mit.edu\n"
repltxt +=  " *  Brendan Dolan-Gavitt   brendandg@gatech.edu\n"
repltxt +=  " * \n"
repltxt +=  " * This work is licensed under the terms of the GNU GPL, version 2. \n"
repltxt +=  " * See the COPYING file in the top-level directory. \n"
repltxt +=  " * \n"


# populate foo...
# cd hg/panda
# find . -exec grep -H PANDABEGIN '{}' \; > list_of_files_containing_panda_comments
x = open("list_of_files_containing_panda_comments")

for line in x:
    foo = re.search("(.*):", line)
    if foo:
        fn = foo.groups()[0]
        foo1 = re.search("panda-comment", fn)
        foo2 = re.search("list_of_files_containing_panda_comments", fn)
        if foo1 or foo2:
            # bogon
            continue
        print fn
        new_lines = ""
        state = 0
        for line in open(fn):
            if state == 0:
                # looking for begin comment
                foo = re.search("(.*)%s(.*)" % PBC, line)            
                if foo:
                    # found begin comment
                    (before_stuff, after_stuff) = foo.groups()
                    new_lines += "%s%s\n" % (before_stuff, PBC)
                    new_lines += repltxt
                    # treat everything after begin comment as if its a new line
                    line = after_stuff
                    # now looking for end comment
                    state = 1
                else:
                    # did not find 
                    new_lines += line
            if state == 1:
                # looking for end comment
                foo = re.search("(.*)%s(.*)" % PEC, line)
                if foo:
                    # found end comment
                    (before_stuff, after_stuff) = foo.groups()
                    # discard before stuff
                    new_lines += "%s%s\n" % (PEC, after_stuff)
                    # just copy the rest
                    state = 2
                    continue
                else:
                    # still haven't found end comment -- discard line
                    pass
            if state == 2:   
                new_lines += line
        open(fn, "w").write(new_lines)

