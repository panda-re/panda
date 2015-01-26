Panda testing framework
=======================

A dead simple testing framework for Panda.  Here's the idea.
You write bash scripts that each run qemu on a particular replay
with some constellation of commandline params and plugins.
The script must generate some kind of output with panda and collect that output into a single file.
That output is blessed and squirreled away as a reference by you.
Later, you run that same script using a different version of panda
and compare new output with blessed reference.
If the outputs differ, either you need to bless the new one or
you should investigate what is broken in panda.  

There are a couple of wrinkles here.
First, panda + plugins don't typically generate output in a file (yet).
So you will have to change your plugin to do that.
I'd suggest arranging for it to log with pandalog.
Second, your output must be the same for every replay.
So don't include timing numbers or datetime or anything that would differ
only incidentally from one run to the next. 

For an example of such a script, look at tests/asidstory1/asidstory1.bash.


Set up
------

The first time you use this framework you will have to run all of the tests
and generate known good outputs.
Unless those are in git and you can just retrieve them?
That would seem like a good idea but it would limit the size of outputs,
and would really mean we should be storing inputs in git too.
The latter is a bad idea because inputs are replays which are too big for that to make sense.

Create or re-create the reference outputs with this commandline.

   ./all.bash ref regressiondir

where `regressiondir` is a safe place where these known good outputs will be 
deposited.
That directory should end up with one reference output per test.

NB: You will have to create the directory `regressiondir/outputs`

Testing
-------

You can run all the tests and determine if any generate output that differs
from reference with the following.

   ./all.bash test regressiondir

You will be told which tests succeed and which fail as well as time required
for each.


Details
-------

Ok this is a VERY SIMPLE framework.
You write scripts that test something in PANDA.

If the test is named `foo`, then the script should be in `./tests/foo/foo.bash`.  
Yes, its a bash script.  
Obviously, you can have that bash script run a python script.
The script must take one argument, the regressiondir.
And it should put all of its test output in the file `regressiondir/outputs/foo.out`,
for test `foo`.

That's it.  
If you create that script and it creates that file, then `all.bash`
should find it and run tha test along withe others and pretty much work.




