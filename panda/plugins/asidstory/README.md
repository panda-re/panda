Plugin: asidstory
===========

Summary
-------

The `asidstory` plugin identifies the different processes that exist in a replay and the portions of the replay in which they were active. It also draws a picture of this graphically (well, in ASCII art). This is very helpful for identifying the PID, process names, address space identifiers (ASIDs), and instruction ranges of interest in a replay.  It is a good first step to perform when analyzing a replay.

This plugin collects the set of asids (cr3 on x86) that are ever observed during
a replay (checking just before each bb executes).  For each asid,
the plugin, further, keeps track of the first instruction at which it
is observed, and also the last.  Together, these two tell us for
what fraction of the replay an asid (and thus the associated process)
existed.  Upon exit, this plugin dumps this data out to a file
"asidstory" but also displays it in an asciiart graph.  At the bottom
of the graph is a set of indicators you can use to choose a good
rr instruction count for various purposes.

Note that `asidstory` is updated with each change in address space id, so the
file can be checked for intermediate status during replay execution.

While a replay is running, you can monitor its progress by using something like:

     watch cat asidstory

If pandalog output is enabled, the asidstory file will not be generated.
This information will be logged to the pandalog file instead.

Sample asidstory output file:

```
  Count   Pid              Name/tid      Asid    First         Last
    239     0          [Idle  / 0]4     39000  5169232  ->  7821664
    218   408    [csrss.exe  / 424]   6330000   437610  ->  6965698
    209   408    [csrss.exe  / 440]   6330000   441751  ->  7752438
    180   408    [csrss.exe  / 444]   6330000   870406  ->  7826129
    180     4        [System  / 24]     39000  2820706  ->  7818745
    142   264  [win_mt_sf_moref  /    c5ae000   331261  ->  4065153
    118     0           [Idle  / 0]     39000   926850  ->  7747954
    115     4       [System  / 296]     39000   258436  ->  7746411
     56     4       [System  / 256]     39000   448435  ->  6951671
     53     0          [Idle  / 0]2     39000   926903  ->  6957618
     51  1732  [explorer.exe  / 172   a64c000   258336  ->  5523697
     44   264  [win_mt_sf_moref  /2   c5ae000   439870  ->  3641250
     35   236     [cmd.exe  / 240]2   c580000  4070318  ->  5093133
     33     0         [Idle  / 0]12     39000  7445624  ->  7498470
     30   236      [cmd.exe  / 240]   c580000  4068146  ->  5110839
     24     4      [System  / 296]5     39000  5926559  ->  7496789
     19   236     [cmd.exe  / 240]5   c580000  4201362  ->  5050839
     19     0         [Idle  / 0]10     39000  6383046  ->  7121383
     19     4       [System  / 56]2     39000  6363377  ->  7122094
     17  1732  [explorer.exe  / 174   a64c000  4194681  ->  6720140
     16     0          [Idle  / 0]7     39000  5643867  ->  5688941
     15     4      [System  / 256]2     39000  5587581  ->  5619891
     15     0          [Idle  / 0]6     39000  5591977  ->  5619170
     15   408   [csrss.exe  / 444]5   6330000  5927154  ->  7493614
     13   408   [csrss.exe  / 424]2   6330000  2041793  ->  6632892
     12   488   [lsass.exe  / 1200]   6810000  5639932  ->  7770937
     12   408   [csrss.exe  / 444]3   6330000  5586087  ->  5627918
     12   408   [csrss.exe  / 440]6   6330000  4199056  ->  5075816
     12  1732  [explorer.exe  / 173   a64c000  6187778  ->  6469198
     10  1724  [wuauclt.exe  / 1760   a5ff000  5523797  ->  7662295
      9   800  [svchost.exe  / 824]   76d7000  6749178  ->  7433837
      9   408   [csrss.exe  / 244]2   6330000  5214029  ->  5217617
      9     4      [System  / 296]2     39000  5645346  ->  5659537
      9     0         [Idle  / 0]14     39000  7662448  ->  7670159
      8   800  [svchost.exe  / 440]   76d7000  6770867  ->  6823448
      7  1732  [explorer.exe  / 173   a64c000  4182542  ->  6651801
      7   264  [win_mt_sf_moref  /9   c5ae000  3644088  ->  3716256
      7   264  [win_mt_sf_moref  /6   c5ae000   940235  ->  4070177
      7   432  [winlogon.exe  / 168   64f5000  7498620  ->  7579810
      6   408   [csrss.exe  / 444]4   6330000  5647165  ->  5663894
      6   408    [csrss.exe  / 244]   6330000  5213923  ->  5737277
      6   408   [csrss.exe  / 440]8   6330000  6769697  ->  6774012
      6     4      [System  / 296]6     39000  7663974  ->  7669090
      6   408   [csrss.exe  / 440]2   6330000   630632  ->  3725004
      5   408   [csrss.exe  / 448]4   6330000  6237099  ->  6272939
      5   408    [csrss.exe  / 448]   6330000  5815589  ->  5860225
      5  1732  [explorer.exe  / 175   a64c000  5177175  ->  5213823
      5   264  [win_mt_sf_moref  /    c5ae000   629367  ->   632848
      5   236     [cmd.exe  / 240]4   c580000  4201308  ->  5073608
      4  1732  [explorer.exe  / 173   a64c000  5929375  ->  5950133
      4   408   [csrss.exe  / 448]3   6330000  5980882  ->  6015297
      4     0         [Idle  / 0]11     39000  6651953  ->  6684289
      4   408   [csrss.exe  / 448]2   6330000  5893740  ->  5926406
      4  1732  [explorer.exe  / 172   a64c000  6015818  ->  6034207
      4   264  [win_mt_sf_moref  /7   c5ae000  1040015  ->  1059118
      4  1732  [explorer.exe  / 174   a64c000  6363746  ->  6382894
      3   408   [csrss.exe  / 424]3   6330000  3641962  ->  3643935
      3   408   [csrss.exe  / 440]4   6330000  1092726  ->  1092732
      3   408   [csrss.exe  / 440]7   6330000  6769591  ->  6769597
      3     4      [System  / 296]3     39000  5702833  ->  5703395
      3   432  [winlogon.exe  / 468   64f5000  6988563  ->  6989494
      3   488  [lsass.exe  / 1200]3   6810000  7469208  ->  7472982
      3   408   [csrss.exe  / 440]5   6330000  1192807  ->  1192813
      3   488  [lsass.exe  / 1200]2   6810000  6850536  ->  6854310
      3   408   [csrss.exe  / 440]3   6330000  1059218  ->  1059224
      3     4       [System  / 56]3     39000  6633044  ->  6633260
      3     4       [System  / 68]2     39000  5739047  ->  5739731
      3     4       [System  / 64]3     39000  7579962  ->  7580369
      3  1724  [wuauclt.exe  / 1765   a5ff000  7304171  ->  7318616
      3     0          [Idle  / 0]8     39000  5703547  ->  5708410
      3  1724  [wuauclt.exe  / 1762   a5ff000  5523851  ->  5538392
      3     0          [Idle  / 0]3     39000  5164492  ->  5165445
      3  1724  [wuauclt.exe  / 1764   a5ff000  5739885  ->  5754338
      3     0         [Idle  / 0]13     39000  7583478  ->  7596724
      3   236     [cmd.exe  / 240]6   c580000  4205300  ->  4206819
      3   264  [win_mt_sf_moref  /8   c5ae000  1188325  ->  1192707
      3   264  [win_mt_sf_moref  /5   c5ae000   929661  ->   937391
      3     0          [Idle  / 0]9     39000  5737429  ->  5738898
      3  1732  [explorer.exe  / 176   a64c000  5214511  ->  5214738
      3   236     [cmd.exe  / 240]3   c580000  4197075  ->  4198956
      3   408   [csrss.exe  / 424]4   6330000  4210968  ->  4210974
      3   408   [csrss.exe  / 440]9   6330000  7580522  ->  7583326
      3   236     [cmd.exe  / 240]9   c580000  5095843  ->  5098450
      3   236     [cmd.exe  / 240]7   c580000  4213196  ->  4215084
      3     4       [System  / 24]3     39000  7091661  ->  7102036
      3     4        [System  / 64]     39000  3641402  ->  3641809
      3   408   [csrss.exe  / 444]2   6330000  5174942  ->  5176330
      3     4        [System  / 68]     39000  5176482  ->  5177022
      3   408   [csrss.exe  / 424]5   6330000  4211074  ->  4213043
      3     4        [System  / 56]     39000  6015449  ->  6015665
      3     4       [System  / 24]2     39000  5708559  ->  5716036
      3     4       [System  / 64]2     39000  7433989  ->  7435567
      2     0          [Idle  / 0]5     39000  5538492  ->  5538492
      2  1724  [wuauclt.exe  / 1763   a5ff000  5739831  ->  5739831
      2     4      [System  / 296]4     39000  5926506  ->  5926506
      2   236     [cmd.exe  / 240]8   c580000  5075916  ->  5075916
      2   408   [csrss.exe  / 448]5   6330000  6415824  ->  6415824
      2   264  [win_mt_sf_moref  /4   c5ae000   929610  ->   929610
      2   264  [win_mt_sf_moref  /3   c5ae000   462588  ->   462588

[explorer.exe  / 172 : [#####                                             ###                      ]
     [System  / 296] : [  #   ##   #       #                  # #       ##   ###      #    #  #  ##]
[win_mt_sf_moref  /  : [   #########       #               ####                                    ]
  [csrss.exe  / 424] : [    # # #                  ########    ###########      # # ### ###        ]
[win_mt_sf_moref  /2 : [    # # ###                #      #                                        ]
  [csrss.exe  / 440] : [    # #  ###########                   ##       #    ### #    #    #  #  ##]
     [System  / 256] : [    #   # #                #                            # #   # ###        ]
[win_mt_sf_moref  /3 : [    #                                                                      ]
[win_mt_sf_moref  /  : [      #                                                                    ]
 [csrss.exe  / 440]2 : [      #                            #                                       ]
  [csrss.exe  / 444] : [        #          ########        #    #       ##   ##   ### ### # #######]
         [Idle  / 0] : [        ##                                       #   ### #        ##  ## ##]
        [Idle  / 0]2 : [        #                                        #      #     ## ##        ]
[win_mt_sf_moref  /4 : [        #                                                                  ]
[win_mt_sf_moref  /5 : [        #                                                                  ]
[win_mt_sf_moref  /6 : [         #                        #    #                                   ]
[win_mt_sf_moref  /7 : [         ##                                                                ]
 [csrss.exe  / 440]3 : [          #                                                                ]
 [csrss.exe  / 440]4 : [          #                                                                ]
[win_mt_sf_moref  /8 : [           #                                                               ]
 [csrss.exe  / 440]5 : [           #                                                               ]
 [csrss.exe  / 424]2 : [                   #                    #                      #           ]
      [System  / 24] : [                           #            #        #   ##    ###    # #######]
      [System  / 64] : [                                  #                                        ]
 [csrss.exe  / 424]3 : [                                  #                                        ]
[win_mt_sf_moref  /9 : [                                  ##                                       ]
    [cmd.exe  / 240] : [                                      # #       #                          ]
   [cmd.exe  / 240]2 : [                                       ##       #                          ]
[explorer.exe  / 173 : [                                        #                      #           ]
[explorer.exe  / 174 : [                                        #                 #   # #          ]
   [cmd.exe  / 240]3 : [                                        #                                  ]
 [csrss.exe  / 440]6 : [                                        #       #                          ]
   [cmd.exe  / 240]4 : [                                        #       #                          ]
   [cmd.exe  / 240]5 : [                                        #       #                          ]
   [cmd.exe  / 240]6 : [                                        #                                  ]
 [csrss.exe  / 424]4 : [                                        #                                  ]
 [csrss.exe  / 424]5 : [                                        #                                  ]
   [cmd.exe  / 240]7 : [                                        #                                  ]
   [cmd.exe  / 240]8 : [                                                #                          ]
   [cmd.exe  / 240]9 : [                                                #                          ]
        [Idle  / 0]3 : [                                                 #                         ]
        [Idle  / 0]4 : [                                                 #   ##  ###### # ##### ###]
 [csrss.exe  / 444]2 : [                                                 #                         ]
      [System  / 68] : [                                                 #                         ]
[explorer.exe  / 175 : [                                                 #                         ]
  [csrss.exe  / 244] : [                                                 #    #                    ]
 [csrss.exe  / 244]2 : [                                                 #                         ]
[explorer.exe  / 176 : [                                                 #                         ]
[wuauclt.exe  / 1760 : [                                                    #             #  #   # ]
[wuauclt.exe  / 1762 : [                                                    #                      ]
        [Idle  / 0]5 : [                                                     #                     ]
 [csrss.exe  / 444]3 : [                                                     #                     ]
    [System  / 256]2 : [                                                     #                     ]
        [Idle  / 0]6 : [                                                     #                     ]
 [lsass.exe  / 1200] : [                                                      #             #    ##]
        [Idle  / 0]7 : [                                                      #                    ]
    [System  / 296]2 : [                                                      #                    ]
 [csrss.exe  / 444]4 : [                                                      #                    ]
    [System  / 296]3 : [                                                      #                    ]
        [Idle  / 0]8 : [                                                      #                    ]
     [System  / 24]2 : [                                                      #                    ]
        [Idle  / 0]9 : [                                                      #                    ]
     [System  / 68]2 : [                                                      #                    ]
[wuauclt.exe  / 1763 : [                                                       #                   ]
[wuauclt.exe  / 1764 : [                                                       #                   ]
  [csrss.exe  / 448] : [                                                       ##                  ]
 [csrss.exe  / 448]2 : [                                                        #                  ]
    [System  / 296]4 : [                                                        #                  ]
    [System  / 296]5 : [                                                        #              #   ]
 [csrss.exe  / 444]5 : [                                                        #              #   ]
[explorer.exe  / 173 : [                                                        #                  ]
 [csrss.exe  / 448]3 : [                                                         #                 ]
      [System  / 56] : [                                                         #                 ]
[explorer.exe  / 172 : [                                                         #                 ]
[explorer.exe  / 173 : [                                                           ###             ]
 [csrss.exe  / 448]4 : [                                                           ##              ]
     [System  / 56]2 : [                                                            ##  #   #      ]
[explorer.exe  / 174 : [                                                            ##             ]
       [Idle  / 0]10 : [                                                             #  #   #      ]
 [csrss.exe  / 448]5 : [                                                             #             ]
     [System  / 56]3 : [                                                               #           ]
       [Idle  / 0]11 : [                                                               #           ]
[svchost.exe  / 824] : [                                                                #     ##   ]
 [csrss.exe  / 440]7 : [                                                                #          ]
 [csrss.exe  / 440]8 : [                                                                #          ]
[svchost.exe  / 440] : [                                                                ##         ]
[lsass.exe  / 1200]2 : [                                                                 #         ]
[winlogon.exe  / 468 : [                                                                  #        ]
     [System  / 24]3 : [                                                                   #       ]
[wuauclt.exe  / 1765 : [                                                                     #     ]
     [System  / 64]2 : [                                                                       #   ]
       [Idle  / 0]12 : [                                                                       #   ]
[lsass.exe  / 1200]3 : [                                                                       #   ]
[winlogon.exe  / 168 : [                                                                       ##  ]
     [System  / 64]3 : [                                                                        #  ]
 [csrss.exe  / 440]9 : [                                                                        #  ]
       [Idle  / 0]13 : [                                                                        #  ]
       [Idle  / 0]14 : [                                                                         # ]
    [System  / 296]6 : [                                                                         # ]
```

In the top table,

* `Count` is the number of times that particular process was observed at an ASID change.
* `First` and `Last` are replay instruction counts for first and last sightings of this process

In the bottom visualization, time is presented horizontally: the start of the replay is denoted `[` and the end of the replay is `]`.
The replay is divided up into `width` cells, and if a process is seen to run at all during a cell, a hash mark `#` is printed.

Arguments
---------

* `width`: the width of the diagram (minimum 80, default 100)
* `summary`: output summary information only, only works with pandalog enabled

Dependencies
------------

Depends on the **osi** plugin to provide OS introspection information. See the documentation for the OSI plugin for more details.

APIs and Callbacks
------------------

None.

Example
-------

To run `asidstory` on a Windows XP 32-bit recording with a 180 character wide diagram:

`$PANDA_PATH/i386-softmmu/panda-system-i386 -replay foo -os windows-32-xpsp3 -panda osi -panda winxpx86intro -panda asidstory:width=180`
