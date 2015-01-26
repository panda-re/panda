Panda testing framework
=======================


Set up
------

The first time you use this framework you will have to run all of the tests
and generate known good outputs.  Unless those are in git and you can just
retrieve them?  

Create the reference outputs with this commandline.

  ./all.bash ref regressiondir

where `regressiondir` is a safe place where these known good outputs will be 
deposited.  That directory should have one reference output per test.

NB: You will also have to create the directory `regressiondir/outputs`

Testing
-------

You can run all the tests and determine if any generate output that differs
from reference with the following.

  ./all.bash test regressiondir

The output will tell you which tests succeed and which fail, will time each
test, and will give you a summary at the end.  


Details
-------

Ok this is a VERY SIMPLE framework.
You write scripts that test something in PANDA.
If the test is named foo, then the script should be in `./tests/foo/foo.bash`.  
The script should take one argument, the regressiondir.
And it should put all of its test output in one file `regressiondir/outputs/foo.out`.

That's it.  If you create that script and it creates that file, then all.bash
should pretty much work.



