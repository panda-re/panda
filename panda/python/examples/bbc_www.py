#!/usr/bin/env python3

'''
Example use of a PyPlugin complete with a flask webserver
'''

from pandare import Panda, PyPlugin

panda = Panda(generic="x86_64")

class BasicBlockCount(PyPlugin):
    def __init__(self, panda):
        self.bb_count = 0

        @panda.cb_before_block_exec
        def my_before_block_fn(_cpu, _trans):
            self.bb_count += 1

    def webserver_init(self, app):
        @app.route("/")
        def test_index():
            return """<html>
            <body>
                <p>
                    Basic Block Count: <span id="bb_count">""" + str(self.bb_count) +  """</span>
                </p>
            </body>
            </html>"""

@panda.queue_blocking
def driver():
    panda.revert_sync("root")
    assert(panda.run_serial_cmd("sleep 10"))
    panda.end_analysis()

panda.pyplugins.enable_flask(host='0.0.0.0')
panda.pyplugins.load(BasicBlockCount)
panda.pyplugins.serve()

panda.run()
