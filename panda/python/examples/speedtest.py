#!/usr/bin/env python3
'''
Use the speedtest plugin to inject synthetic delays and observe impact on guest performance.
'''

from pandare import Panda
panda = Panda(generic="x86_64")

''' Some results:
Delay    user blocks/int       kern/userspace ratio               whoami time (real, user, sys)
----------------------------------------------------------

0       160                     0                           0.10,   0.02,   0.07
20      ~60-100                 ~0.95                       error,  3.6,    8.6
40      ~35-100                 ~0.95                       error,  6.3,    15.3
100     ~35-100                 ~0.95                       error,  12.0,   35.88

500     2-8                     0.99                        DNF
'''


@panda.queue_blocking
def driver():
    panda.revert_sync('root')
    panda.load_plugin('speedtest', args={'ratio': True, 'ints': True, 'delay': 200, 'final_log': True} )

    print("\nGuest output:", panda.run_serial_cmd("time whoami", timeout=1000))

    panda.unload_plugin('speedtest')

    panda.end_analysis()

panda.run()
