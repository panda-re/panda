PANDA User Manual
=================


Overview
--------

What is PANDA.  What are some common uses.
    
    
Quickstart
----------

10 minute intro to what you can do with PANDA.
    
### Record

### Replay

### Analysis


A Tour of Qemu Tour
-------------------

What does a PANDA user need to know about Qemu?

### Qemu's Monitor

### Emulation details

### What is env?

### Virtual vs physical memory

### Panda access to Qemu data structures


Record / Replay
---------------

What is it?  How does it work?
    Why is it important?   
  [Include explanation of snapshot & ndlog format?]


Plugin Architecture
-------------------
    
### Callback list with explanation of semantics and where and when each occurs in emulation

### Order of execution

### Plugin-plugin interaction

#### Plugin callbacks

#### Plugin API


Plugin Zoo
----------

### scissors

### asidstory

### syscalls2

### taint2

### file_taint

### tainted_branch

### tainted_instructions

### Others?    

    
Pandalog
--------

Why and what for.  Probably just the stuff in pandalog.md
    
    
LLVM
----
        
### Execution

### How to use it for analysis


Wish List
---------

What is missing from PANDA?  What do we know how to do but just don't have time for?  What do we not know how to do?

    