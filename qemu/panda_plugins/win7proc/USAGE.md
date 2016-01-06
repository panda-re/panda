Plugin: win7proc
===========

Summary
-------

The `win7proc` plugin provides Windows 7 introspection into a number of interesting system calls, including those related to

* processes
* the registry
* sections (shared memory)
* the file system
* LPC ports (Local Procedure call)
* shared memory

The plugin uses domain knowledge about how to understand pointers to important Windows types such as handles, objects, and EPROCESS data structures.
This information is repackaged as `pandalog` entries, as described in `win7proc.proto` and (mostly) parseable by `pandalog_reader`.

The pandalog output can be consumed by the script `qemu/scripts/procstory.py` to generate an ASCII-art visualization of process births and deaths.
As with `asidstory`, when a replay is generating `win7proc` pandalog output, the script can be used to generate a somewhat live view.

     watch scripts/procstory.py foo.plog

Sample output for `procstory.py`:

     max_instr = 9349975980                                                                               
     ==========================================                                                           
      [b]    svchost1 1732-svchost.exe                                                                    
      [b] SearchProt1 1820-SearchProtocol                                                                 
      [i]    svchost2 824-svchost.exe-0-9349975980                                                        
        [i]    WMIADAP1 1968-WMIADAP.exe-b7155159439-d7323653668-p-svchost2                              
      [b]    svchost3 796-svchost.exe                                                                     
      [b]   SearchIn1 780-SearchIndexer.                                                                  
      [b]    svchost4 1048-svchost.exe                                                                    
      [i]   explorer1 1232-explorer.exe-0-9349975980                                                      
        [i]    notepad1 428-notepad.exe-b702390220-d5071152352-p-explorer1                               
        [i]        cmd3 1316-cmd.exe-b5676871135-9349975980-p-explorer1                                  
          [i]   ipconfig1 2004-ipconfig.exe-b8731220644-d8824826414-p-cmd3                               
      [b]    svchost5 1208-svchost.exe                                                                    
      [b]    svchost6 664-svchost.exe                                                                     
      [b]      lsass1 424-lsass.exe                                                                       
      [b]      csrss1 284-csrss.exe                                                                       
      [b]        dwm1 1236-dwm.exe                                                                        
      [b]    svchost7 932-svchost.exe                                                                     
      [b]   winlogon1 360-winlogon.exe                                                                    
      [i]      csrss2 332-csrss.exe-0-9349975980                                                          
        [i]    conhost2 1832-conhost.exe-b5682605261-9349975980-p-csrss2                                 
      [b]    svchost8 616-svchost.exe                                                                     
      [b]   services1 408-services.exe                                                                    
      [b]        lsm1 432-lsm.exe                                                                         
      [b]   taskhost1 1272-taskhost.exe                                                                   
      [i]    svchost9 540-svchost.exe-0-9349975980                                                        
        [i]    dllhost1 1240-dllhost.exe-b5148567550-d5976293438-p-svchost9                              
      [b]   svchost10 1848-svchost.exe                                                                    
      [b]   WmiPrvSE1 1748-WmiPrvSE.exe                                                                   
      [b] SearchFilt1 1324-SearchFilterHo                                                                 
      [i]     choice1 1836-choice.exe-0-d3258090694                                                       
      [b]    conhost1 1876-conhost.exe                                                                    
      [i]        cmd1 1360-cmd.exe-0-9349975980                                                           
        [i]        cmd2 1240-cmd.exe-b3295106704-d3359992160-p-cmd1                                      
        [i]   svchost11 1672-svchost.exe-b3296266508-d3797733522-p-cmd1                                  
        [i]   tasklist1 1580-tasklist.exe-b3863058292-d5127955252-p-cmd1                                 
        [i]   svchost12 1344-svchost.exe-b3864065823-d4801454245-p-cmd1                                  
        [i]     choice2 740-choice.exe-b5142012434-d9286134975-p-cmd1                                    
        [i]        cmd4 560-cmd.exe-b9301579103-d9319514374-p-cmd1                                       
        [i]   svchost12 1344-svchost.exe-b9311689913-9349975980-p-cmd1                                   
      [i]    unknown1 0-unknown-0-d5016269325                                                            
     Note: A process is either [b]oring or [i]nteresting. It is boring iff                                
             (1) we did not see its creation,                                                             
             (2) we did not see its termination,                                                          
         and (3) it has no children                                                                       
     ==========================================                                                           
        svchost2 :  |?------------------------------------------------------------+------------------?|   
        WMIADAP1 :  |                                                             CT                  |   
       explorer1 :  |?-----+-----------------------------------------+-------------------------------?|   
        notepad1 :  |      C------------------------------------T    |                                |   
            cmd3 :  |                                                C-------------------------+-----?|   
       ipconfig1 :  |                                                                          CT     |   
          csrss2 :  |?-----------------------------------------------+-------------------------------?|   
        conhost2 :  |                                                C-------------------------------?|   
        svchost9 :  |?-------------------------------------------+-----------------------------------?|   
        dllhost1 :  |                                            C------T                             |   
         choice1 :  |?--------------------------T                                                     |   
            cmd1 :  |?---------------------------+----+---------+-----------------------------------+?|   
            cmd2 :  |                            T    |         |                                   | |   
       svchost11 :  |                            C---T|         |                                   | |   
       tasklist1 :  |                                 C---------T                                   | |   
       svchost12 :  |                                 C-------T |                                   | |   
         choice2 :  |                                           C-----------------------------------T |   
            cmd4 :  |                                                                               T |   
       svchost12 :  |                                                                               C?|   
        unknown1 :  |?-----------------------------------------T                                      |   
     ==========================================                                                           
     Legend: [C]reation [T]ermination [?]Unknown [+]Branch                                                
Arguments
---------

* `grab_files`: boolean. Controls whether to dump out any file data written during the replay (by intercepting calls to NtWriteFile). The files will be saved into a directory named `output` in the current directory, which will be created if it does not already exist.

Dependencies
------------

`win7proc` uses `syscalls2` to monitor Windows system calls. Note that because the plugin only supports Windows 7 32-bit, you should always load `syscalls2` with the `windows7_x86` profile.

APIs and Callbacks
------------------

None.

Example
-------

To run `win7proc` on a Windows 7 32-bit recording and generate pandalog file `foo.plog` and dump files:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo -pandalog foo.plog \
        -panda syscalls2:profile=windows7_x86 -panda win7proc:grab_files
