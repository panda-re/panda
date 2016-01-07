
# PANDA Lab 

Tim Leek `tleek@ll.mit.edu`

## Introduction 

In this lab, you will use PANDA to investigate the dynamic behavior of program code and the operating system that contains it.
PANDA is a whole-system dynamic analysis platform based upon the Qemu emulator.
An entire operating system runs under PANDA, which makes it especially useful for situations in which concurrent processes and even kernel activity must be understood.


Further, execution can be recorded and replayed, which is a powerful ability.
Various analysis plugins that run on the execution replay allow visibility into the emulated guest and provide information about what is going on there.
Reverse Engineering with PANDA is typically an iterative process, replaying a recorded execution over and over under different plugins and inspecting output to accumulate better and more complete understanding of behavior.

FYI: [PANDA](https://github.com/moyix/panda) is on github so you can download it and run it on your own (Linux) box.  

#COMMENT STEP END 



## Lab Prerequisites

### SSH Terminal

You will be running PANDA from a Linux machine and will need to be able to log in to that machine via `SSH`. 

1. For OSX latop, you can use the `Terminal` app to run the `ssh` command.
2. For Linux laptop, similarly, you can run `ssh` from any terminal. 
3. For Windows laptop, you will need to install something like [PuTTY](http://www.putty.org/).


### X11 Server

PANDA needs to open an X window on your laptop to represent the emulated guest.  
Thus, you will have to forward X11 traffic from the PANDA linux machine back to your laptop.
You must install an X server on your laptop for this to work. 
Here are a few options.

1. For Linux laptop, there is nothing to install.
2. For OSX laptop, install [XQuartz](http://www.xquartz.org/).
3. For Windows laptop, install [VcXsrv](http://sourceforge.net/projects/vcxsrv/)

#COMMENT STEP END 


## PANDA Introduction

Boot an OS.  Create a PANDA recording.  Replay it.

### Make sure X server is running on your laptop (see Prereq).

### SSH in to the Linux machine from which you will be running PANDA.


For OSX and Linux, use `ssh -X ...` to have X forwarded.  
For Windows ...

### Boot Windows 7 guest with PANDA.

From the ssh Terminal, enter the following.

     ~/panda/qemu/x86_64-softmmu/qemu-system-x86_64  ~/qcows/win7x86-iap-2015.qcow2 -m 1G -k en-us -monitor stdio

Note on that commandline:

* The filename ending with qcow2 is the virtual hard drive plus other machine info
* `-m 1G` gives the emulated guest 1G of RAM
* `-monitor stdio` attaches a Qemu monitor on the terminal.  See later.

This should pop open a window on your laptop with title `PANDA (QEMU)` and begin booting Windows 7 in that window.

**Question: How long does it take Windows 7 to boot under PANDA?** 

#COMMENT STEP END


#### The Qemu monitor

You should also see a *Qemu monitor* prompt in the terminal just after where you typed those commands.
The monitor allows you to interact with the emulator in a variety of ways and should be used with care.
You will use it to create a recording of whole operating system activity shortly.
It will look like this on your terminal.

     QEMU 1.0,1 monitor - type 'help' for more information
     (qemu) 


#COMMENT STEP END


### Log in to guest and poke around

That PANDA window is an entire Windows 7 operating system.  You can log in as user `qemu` with password `infected`.

**Question. How long does it take to open Internet Explorer under PANDA?**

**Question. Can you get to any web pages from IE?**

#COMMENT STEP END

### PANDA (QEMU) Snapshots.

With PANDA you can create and revert to snapshots.
This can be useful, for instance, to undo the ill effects of malware.

In the monitor, type the following.

     info snapshots

You should see something like the following.

     ID        TAG                 VM SIZE                DATE       VM CLOCK
     1         loggedin               468M 2015-12-31 13:20:12   00:08:26.727

Revert, now, to that snapshot by typing the following into the monitor.

     loadvm loggedin

There is an analogous command `savevm name` which will create a new snapshot for the current state.

#COMMENT STEP END


### Record some guest activity

#### Start recording.  From the Qemu monitor, type 

     begin_record iap

#### In the guest, open `Cmd` shell and enter the following.

<b></b>

    cd Desktop
    echo "The quick brown fox jumps over the lazy dog" > foo.txt
    type foo.txt
    move foo.txt bar.txt
    del bar.txt
    ipconfig

#### End recording.  From the Qemu monitor, type 

    end_record iap

The recording is actually two files sitting in the  directory from which you ran PANDA.

    iap-rr-snp
    iap-rr-nondet.log

The first of these is a snapshot of the VM state at the start of recording.  
The second is a log of all nondeterministic inputs to the CPU and RAM (via DMA).
Replay works by first reverting to that snapshot, then running the machine, which will use the nondet log whenever it needs an input.

**Question. How many instructions are in that recording?**

**Question. How big are those files?**

#COMMENT STEP END


### Shut down the Windows 7 guest gracefully.

That is, use the mouse in the guest to shut down that emulated machine.  
This limits corruption in the the qcow2 file.  

#COMMENT STEP END


### Replay that guest activity

You can replay what you recorded with the following command.

     ~/panda/qemu/x86_64-softmmu/qemu-system-x86_64 -m 1G -replay iap
     
During replay, you dont see the graphic window of what happened, although there is a way to access that during replay.
What you do observe is a progress line indicating the fraction of replay and number of instructions completed.
So this isn't very helpful in and of itself.

#COMMENT STEP END

You can re-run that replay with some extra command-line arguments that will essentially give you an instruction trace.

     ~/panda/qemu/x86_64-softmmu/qemu-system-x86_64 -m 1G -replay iap -d in_asm,rr -D qemu.log

This produces a lot of output in the file `qemu.log`.
It is hard to imagine any human being able to make much sense of it.  


#COMMENT STEP END

   
## PANDA Whole System Understanding

Now we are going to try out a couple of PANDA plugins that try to make sense of that replay for you in more familiar terms.

### Asidstory plugin

Often, the first plugin we will run on a replay is the `asidstory` plugin, because it provides a thousand foot view.
An operating system is a complex of processes arranged to behave as though they are all running at the same time.
In order for there to be multiple processes running, the operating system provides an abstraction to physical memory called *virtual* memory.
There is a register, called the ASID or address-space identifier, that contains a pointer to the data structures used to map between virtual and physical memory. 
It is necessarily unique to each process.
On the X86 processor, that register is `CR3`.

The `asidstory` plugin uses the PANDA callback for when the ASID changes, arranging for a function to be called whenever that happens.
It also uses an API from some other plugins that know how to obtain information about the currently running process in Windows 7.
This information is digested and rendered into some fetching ASCII art that depicts when various processes are active during the replay.

You will need two ssh windows open to do this.
In one window, type the following.

     cd ~/panda/qemu
     watch cat asidstory

This is a little Linux magic to write out to the terminal the contents of the file `asidstory` every few seconds.
That file will periodically be rewritten by the plugin.
In another window, type the following.

     cd ~/panda/qemu
     x86_64-softmmu/qemu-system-x86_64 -m 1G -replay iap -panda 'asidstory;osi;win7x86intro'

This will run the replay, with the `asidstory` plugin and the necessary Windows 7 info plugin.  
As the replay progresses, you will see the ascii art evolve, telling you when processes are active and when they are not.
Time is measured in replay instruction counts.

#COMMENT STEP END

**Question.  How many processes do you see in the replay?**

**Question.  Can you see the things you did when you were creating the recording?**

**Question.  Does anything appear to be missing in the replay?**

**Question.  Can you account for everything you see in the replay?**

**Question.  Do you see anything strange?**

#COMMENT STEP END


### Win7Proc plugin

A somewhat different but mostly just deeper analysis is provided by another plugin, oddly named `win7proc`.
This plugin registers callbacks with a variety of Windows 7 system calls.
System calls are how programs interact with the kernel; they are the API to the kernel.
The `win7proc` plugin makes use of additional domain knowledge about how to decipher certain important Windows types like objects, handles, and so on, and writes entries of decoded syscall information to a binary `pandalog`.
That log is very interesting and we will be looking at it soon.

However, first let's try out a nice script that provides a visualization of the process hierarchy of the entire operating system, somewhat like `ps` or `Task Manager`, but threaded through time.
We can run that to get a live update rather like we did with `asidstory`.

Here, too, you'll want to use two ssh windows.
In one window, type the following 

     cd ~/panda/qemu
     watch python scripts/procstory.py iap.plog

It the other window, run the replay with `win7proc` and `syscalls2` plugins as follows

     cd ~/panda/qemu
     x86_64-softmmu/qemu-system-x86_64 -m 1G -replay iap -pandalog iap.plog  -panda 'syscalls2:profile=windows7_x86;win7proc' 

Again, watch the visualization window, where you will see process births and deaths clearly indicated and named.
As with `asidstory`, all process births and deaths are indicated in terms of replay instruction counts.

#COMMENT STEP END


**Question.  Does this view agree with the one you got from `asidstory`?**

**Question.  Are there now fewer things going on in the replay that you don't understand?**

**Question.  Do you see anything strange?**

#COMMENT STEP END


Turns out there was malware installed and running on that guest at the `loggedin` snapshot.  
In particular, it's odd that a system process like `svchost` is being created by `cmd`, isn't it?
Spend some time looking at the `pandalog` to try to understand what is going on.  
Type the following to get a human-readable version of `iap.plog`.

     cd ~/panda/qemu/panda
     pandalog_reader ../iap.plog > iap.plog.txt


#COMMENT STEP END

**Question.  How many lines in iap.plog.txt?**

**Question.  Is there a way you can narrow that down to just the activity of interest?**

**Question.  Can you find the malware and figure out how it works?**

**Question.  What is this malware doing?**

#COMMENT STEP END


### Memsavep plugin

You have now found all the parts of the malware.
But what does that `svchost.exe` program do?
There are a number of ways you can get it off the guest for closer inspection.
Here is one.
The `memsavep` plugin can dump the guest's physical memory at a particular replay instruction.
You can use this dump with another tool (not part of PANDA) called `Volatility` built for forensic analysis of memory dumps.
`Volatility` can extract PE files from memory dumps.

FYI: If you like `Volatility` you can install in on any Linux box with `apt-get install volatility`.

Here's how to use the `memsavep` plugin.  

     cd ~/panda/qemu
     x86_64-softmmu/qemu-system-x86_64 -m 1G -replay iap -panda 'memsavep:percent=50.0'

Actually, you'll have to figure out the correct percent.
When this replay has completed, you'll have a file `memsavep.raw` that is the contents of physical memory at the specified point in the replay.
Now try out these `Volatility` commands to determine what processes are running.

     volatiltity pslist -f ~/panda/qemu/memsavep.raw --profile=Win7SP1x86
     volatiltity psscan -f ~/panda/qemu/memsavep.raw --profile=Win7SP1x86

We don't actually need this output.  But is interesting to note that you can obtain it from the memory dump.

You should be able to get the PID for the process you want to extract using either `asidstory` or `procstory` output.
Here is the `Volatility` command to use to extract that process from a dump and you will have to fill in `PID`.

     volatility procdump -f ~/panda/qemu/memsavep.raw --profile=Win7SP1x86 -p PID --dump-dir .

This will extract the image to the current directory but it will be called something like `executable.pid.exe`.
And you can look at it.  


#COMMENT STEP END

**Question.  Now that you have the binary for `svchost.exe` can you figure out what it is doing?**

### Bigger things

Ok that malware wasnt very interesting.
There is a project, created by a colleague of ours at NYU, Brendan Dolan-Gavitt, that uses PANDA to open and execute malware from a very large feed.
That project is called [Malrec](https://github.com/moyix/panda-malrec).
Malrec takes recordings of malware activity whilst trying to get it to do interesting things.
All of the code to create those recordings is available as well as the recordings themselves.   

We took a single recording from there, recommended by Brendan, and ran it through the `asidstory` and `win7proc` analyses.
The results of those analyses are in `/opt/panda` on the panda machine you have been working on. 

     /opt/panda/3368d295-8d73-4216-8823-128c66872c3c.[plog|asidstory|procstory]
 



**Question.  Can you peer at the PANDA output for running this malware and make sense of what it does and how it gets installed?**




#COMMENT STEP END



#COMMENT LAST LINE