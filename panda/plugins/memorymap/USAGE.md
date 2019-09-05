Plugin: asidstory
===========

Summary
-------

The `asidstory` plugin identifies the different processes that exist in a replay and the portions of the replay in which they were active. It also draws a picture of this graphically (well, in ASCII art). This is very helpful for identifying the PID, process names, address space identifiers (ASIDs), and instruction ranges of interest in a replay.  It is a good first step to perform when analyzing a replay.

`asidstory` creates a single output file named `asidstory` in the current directory. This is not currently configurable.

Note that `asidstory` writes its output file many times throughout the replay. So while a replay is running, you can watch its progress over the course of a replay by using something like 

     watch cat asidstory

Sample output:

        Count   Pid        Name              Asid       First            Last                            
        50487  1732     svchost          3f97e360     3026269  ->  9349488231                            
        20925   780  SearchInde          3f97e320    71640505  ->  9303407899                            
        15477   332       csrss          3f97e040     2990411  ->  9349528823                            
         9018     4      System            185000    20402603  ->  9349778621                            
         7374  1232    explorer          3f97e2e0    99202165  ->  9344752977                            
         6828   428     notepad          3f97e3e0   702400395  ->  5577274496                            
         5772   424       lsass          3f97e0e0   104119764  ->  8936289926                            
         4149  1876     conhost          3f97e3c0  3257817401  ->  9331156881                            
         3639  1820  SearchProt          3f97e340    15411590  ->  9349928197                            
         3636  1832    conhost2          3f97e460  5684954287  ->  9339650648                            
         3078  1580    tasklist          3f97e420  3898738772  ->  5129908800                            
         2751   824    svchost2          3f97e1c0    52169289  ->  9336684266                            
         1569  1748    WmiPrvSE          3f97e400  1601087954  ->  9317628994                            
         1464  1360         cmd          3f97e3a0  3270569060  ->  9330663249                            
         1101   540    svchost9          3f97e120  1118604589  ->  7027306731                            
         1008   664    svchost6          3f97e160   102396900  ->  8835474680                            
          870  1316        cmd3          3f97e440  5681577761  ->  8830446793                            
          780   616    svchost8          3f97e140   331157320  ->  9317632155                            
          687  1048    svchost4          3f97e200    85011953  ->  9317604802                            
          618   432         lsm          3f97e100   663072484  ->  8941092750                            
          444  1208    svchost5          3f97e260   102394623  ->  8918795360                            
          390  1240     dllhost          3f97e420  5150399847  ->  5989025037                            
          387  1968     WMIADAP          3f97e420  7161460146  ->  7324830774                            
          354  1344   svchost13          3f97e380  3904610653  ->  4803101974                            
          351   284      csrss2          3f97e060   106292836  ->  8628933540                            
          318  2004    ipconfig          3f97e420  8737453423  ->  8830495167                            
          300   408    services          3f97e080   660415410  ->  8581159359                            
          294  1672   svchost11          3f97e420  3314811903  ->  3799411684                            
          123  1272    taskhost          3f97e280   723813889  ->  8790660459                            
          114   740     choice2          3f97e380  5143534503  ->  9287393999                            
          108   560        cmd4          3f97e380  9308064708  ->  9320711988                            
          105   796    svchost3          3f97e1a0    69290217  ->  8126603222                            
           96  1240        cmd2          3f97e380  3312092859  ->  3361174070                            
           75   932    svchost7          3f97e1e0   323596365  ->  7561652077                            
           75  1344   svchost14          3f97e420  9320728023  ->  9349923943                            
           51  1836      choice          3f97e380  3257814441  ->  3259377979                            
           39  1236         dwm          3f97e180   244735299  ->  5752146043                            
           15  1324  SearchFilt          3f97e2a0  2447938156  ->  4886203780                            
           12  1848   svchost10          3f97e300  1231774564  ->  6476638884                            
           12   360    winlogon          3f97e0c0   327663206  ->  8216454647                            
                                                                                                         
          csrss : [#####################################################################################]
        svchost : [###### #############################  ###############################################]
     SearchProt : [#####################################################################################]
         System : [#####################################################################################]
       svchost2 : [### ######## #######################   ######### ####################################]
       svchost3 : [#                                ##         # ##    #     #    #         #           ]
     SearchInde : [### ######## ####### ###############   ######### ####################################]
       svchost4 : [################# # ################  ########## ####################################]
       explorer : [#####################################################################################]
       svchost5 : [# ###### #     #       # ### #  ####  # ######## # ### # #   #    ##   #    #    #   ]
       svchost6 : [### #       #           #### #    ##  #  ## ####            ###     ##        ###    ]
          lsass : [##    ## # #            ### ############### ####  ##  #        ####  #   #    #  #   ]
         csrss2 : [##  # ######   #      # ######  ####  #####  ### # ###    #  #   ## #       ###      ]
            dwm : [  # ###                 #                     #    ##                                ]
       svchost7 : [  ##    #      #         #        #   ##  #  ##              #      #                ]
       winlogon : [  #                         #                                             #          ]
       svchost8 : [   ## #    ##        ## #### #######   ####  ### #### #        # ##            #    #]
       services : [      ##                #  ###  ## #              #  #        #     #         #      ]
            lsm : [      #         #             #  ##    #    ###   ## #            #              #   ]
        notepad : [      ##############################  ##########  #                                  ]
       taskhost : [      #     #                     ##  ##      ##   # ##                      ###     ]
       svchost9 : [          #             #       ## #   ##     #   ##          ##                     ]
      svchost10 : [           #                                              #                          ]
       WmiPrvSE : [              #             ########   ######         #        #            #    #  #]
     SearchFilt : [                      #   #               # #                                        ]
         choice : [                             #                                                       ]
        conhost : [                             #######  ### #####                                     #]
            cmd : [                             ##   ##          #                                     #]
           cmd2 : [                              #                                                      ]
      svchost11 : [                              #####                                                  ]
       tasklist : [                                   #  #########                                      ]
      svchost13 : [                                   #  ######                                         ]
        choice2 : [                                              #                                     #]
        dllhost : [                                              ## ##   #                              ]
           cmd3 : [                                                   ##  #    ##      #    # # # ##    ]
       conhost2 : [                                                   ##################################]
        WMIADAP : [                                                                 ##                  ]
       ipconfig : [                                                                               ##    ]
           cmd4 : [                                                                                    #]
      svchost14 : [                                                                                    #]

In the top table, 
* `Count` is the number of times that particular process was observed at an ASID change.  
* `First` and `Last` are replay instruction counts for first and last sightings of this process

In the bottom visualization, time is presented horizontally: the start of the replay is denoted `[` and the end of the replay is `]`.
The replay is divided up into `width` cells, and if a process is seen to run at all during a cell, a hash mark `#` is printed.

Arguments
---------

* `width`: the width of the diagram (minimum 80, default 100)


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
