# Panda testing framework

A dead simple testing framework for Panda record/replay.  Here's the idea. You write Python scripts that will each run a record/replay with some plugins and parameters.

 The script must
generate some kind of output with panda and collect that output into a
single file.  That output is blessed and squirreled away as a
reference by you.  Later, you run that same script using a different
version of panda and compare new output with blessed reference.  If
the outputs differ, either you need to bless the new one or you should
investigate what is broken in panda.

There are a couple of wrinkles here.  First, panda + plugins don't
typically generate output in a file (yet).  So you will have to change
your plugin to do that.  I'd suggest arranging for it to log with
pandalog.  Second, your output must be the same for every replay.  So
don't include timing numbers or datetime or host pointers or anything
that would differ only incidentally from one run to the next.

The `ptest.py` script controls everything.

NB: you need to set the `PANDA_REGRESSION_DIR` env variable for any
of this to work.  This is where all your regression testing will happen

# Testing

Tests are located in the `testing/` folder. Which tests to run are specified in the `config.testing` file.

## Set up/initialization

The first time you use this framework you will have to setup all of your tests. 

`ptest.py init`         (initializes testing - clears PANDA_REGRESSION_DIR, downloads some qcows)
`ptest.py setup`        (runs setup.py for all enabled tests, doesn't download qcows)

## Blessing 

Once you've run the setup scripts, you must generate known good outputs. `ptest.py bless` will run the test scripts, and place the output in the `/blessed` directory.

`ptest.py bless`

## Run tests

Now, `ptest.py test` will run all the tests inside the `/tmpout` dir, then compare the output to the blessed output. If there are inconsistencies, the test fails.

# Writing tests

For each thing that you want to test, create a `-setup.py` and `-test.py` script in a new folder in `testing/`. 

At a minimum, your setup script might create a recording with the `run_debian(cmd, replayname, arch)` helper. Your test script would then replay the recording with the plugins and arguments that you specify.

See the `asidstory` setup and test scripts for an example.
