Plugin: asidstory
===========

Summary
-------

The `asidstory` plugin identifies the different processes that exist in a replay and the portions of the replay in which they were active. It also draws a picture of this graphically (well, in ASCII art). This is very helpful for identifying the PID, process names, and address space identifiers (ASIDs) of interest in a replay, and is often a good first step to perform when analyzing a replay.

`asidstory` creates a single output file named `asidstory` in the current directory. This is not currently configurable.

Note that `asidstory` writes its output file many times throughout the replay. So while a replay is running, you can watch its progress over time by using something like `watch cat asidstory`.

Sample output:

          Count   Pid        Name              Asid        First             Last
      398586283  1720    explorer          3f9b2400      1326328  ->  11662493985
      207940380  1176  msfeedssyn          3f9b2520   7445969821  ->   9961787213
      174122352   364       csrss          3f9b2040         6067  ->  11663129364
      130470361   464       lsass          3f9b20e0     15445277  ->  11661243751
      127711544     4      System            185000       139617  ->  11662977539
      119113847   268   svchost10          3f9b2380   2215112646  ->   5472879351
       93559980  1576    iexplore          3f9b2300   4065084430  ->  11617349854
       73567700   540    dllhost4          3f9b24c0   4619057788  ->  11566751990
       58879469  1884  SearchInde          3f9b2160     16257388  ->  11659818838
       53703344   828    svchost2          3f9b21c0       673354  ->  11659407176
       45411418  1688   explorer2          3f9b2440   1936435945  ->   3368180224
       43587933  1216   iexplore2          3f9b22a0   4880885711  ->  11570555134
       35607382   344      sppsvc          3f9b2320    807413823  ->  11636568504
       30358832  1840  SearchProt          3f9b23a0   1328055150  ->   8585280592
       26046617  1060    svchost3          3f9b2200      1407806  ->  11663037832
       23669908   936    svchost6          3f9b21e0     31608979  ->  11658225052

    [...]

         csrss : [#####################################################################################]
        System : [#####################################################################################]
       conhost : [###################################                  #                               ]
       svchost : [# ##      # # ##   # #####  ##   #  ## ## #    #   ###         ##  #    #######   ###]
        csrss2 : [## # #    ###  ## ######## # ##  #######  #   ###  #####  ########  # ######### # ###]
      services : [## # #            ## #####     #   ### #  ##  #     ####     # #####  # #######   ###]
      svchost2 : [#### ################################# #      #    #####      ####   ########## # ###]
       spoolsv : [#        #              #    #                      ##         #         ######    ##]
      explorer : [############## ################################################################ #####]
      svchost3 : [############################################  ###  #####  #  ################## #####]
         lsass : [##  ##    ###  ## ######## # ########### ########################### ##########   ###]
    SearchInde : [###  ########  ################################### ######  ## ################# # ###]
      svchost4 : [#### #                ###  ### ### ##  #   #  ##    ##         ######   #######   ###]
           lsm : [#     #   ##         ## #     #  #  #               ###                 #######    ##]
      taskhost : [#    #     ##### ### #  #   ##  ## ##  #       #     ##          #      #######    ##]
           dwm : [############            #    #    ###   ###   #      #         #                     ]
      svchost5 : [##         ##  ##########  # ###############  ###  #####   ########  ########## # ###]
      svchost6 : [## # # # ###  #   #  ##### ##### ### # # # #  ##   ### #     # #####  # ####### # ###]
           cmd : [#    #####                                                                           ]
      ipconfig : [######                                                                               ]
      svchost7 : [########   ##     ## ##### #### ##  #  #  #         ####  # #  #####  #########   ###]

Arguments
---------

* `width`: the width of the diagram (minimum 80, default 100)
* `sample_rate`: how often, in terms of number of basic blocks executed, to sample process information. Defaults to every 100 basic blocks.
* `sample_cutoff`: defines the minimum number of samples a process must appear in before it will be included in the output. Defaults to 10.

`asidstory` also supports [pandalog](docs/pandalog.md), and will write information about each process sampled out to the pandalog if you provide a filename with the `-pandalog` argument to QEMU.

Dependencies
------------

Depends on the **osi** plugin to provide OS introspection information. See the documentation for the OSI plugin for more details.

APIs and Callbacks
------------------

None.

Example
-------

To run `asidstory` on a Windows 7 32-bit recording with a 180 character wide diagram:

`$PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo -panda osi -panda win7x86intro -panda asidstory:width=180`
