# 
# PARCOR --- Simple parallell job coordination
# 



import os
import sys
import multiprocessing
import random
import time
import subprocess
import re
import cPickle as pickle

def memory():
    """
    Get node total memory and memory usage
    """
    with open('/proc/meminfo', 'r') as mem:
        ret = {}
        tmp = 0
        for i in mem:
            sline = i.split()
            if str(sline[0]) == 'MemTotal:':
                ret['total'] = int(sline[1])
            elif str(sline[0]) in ('MemFree:', 'Buffers:', 'Cached:'):
                tmp += int(sline[1])
        ret['free'] = tmp
        ret['used'] = int(ret['total']) - int(ret['free'])
    return ret


class Job(object):
    
    def __init__(self, name, cmd_str):
        self.name = name
        self.cmd_str = cmd_str
        # this is the probability we will actually pick it
        self.prob = 1.0
        self.mem_required = 0
        
    def __str__(self):
        return self.name

    def start(self):
        """
        Starts this job and returns immediately
        """
        # note this doesnt block
        print "starting job [%s] cmd_str [%s]" % (self.name, self.cmd_str)
        self.proc = subprocess.Popen(self.cmd_str.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.start_time = time.time()
        self.pid = self.proc.pid

    def is_finished(self):
        """ 
        Returns true if this job is finished
        Also, captures timing and output
        """
        it = 0
        while True:
            it += 1
            if (it > 20):
                raise RuntimeError
            rv = self.proc.poll()
            running1 = (rv is None)
            p = subprocess.Popen("/bin/ps -auwx".split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (s,e) = p.communicate()
            running = False
            for line in s.split('\n'):
                if len(line.split()) < 2:
                    continue
                pids = line.split()[1]
                foo = re.search("^[0-9]+$", pids)
                if foo:
                    pid = int(line.split()[1])
                    if pid == self.pid:
                        running = True
                        break
            if running1 == running:
                break

        if running:
            return False
        else:
            assert (running is False)
            print "Job %s finished -- retval was %d" % (self.name, rv)
            if not (rv == 0):
                print "**** retval non-zero"
                raise RuntimeError        
            # done -- capture output & elapsed time
            self.end_time = time.time()
            self.time_to_finish = self.end_time - time.time()
            (self.stdout, self.stderr) = self.proc.communicate()
            return True    



class JobSet(object):

    def __init__(self, name):
        self.name = name
        self.waiting = set([])
        self.running = set([])
        self.finished = set([])
        self.retired = set([])
        self.num_cores = multiprocessing.cpu_count()
        self.roundnum = 0
        # sleep for 5 sec between rounds
        self.sleep = 5
        self.debug = True

    def dprint(self, msg):
        if self.debug:
            print msg

    def status(self):
        print "%d waiting. %d running. %d finished. %d retired" \
            % (len(self.waiting), len(self.running), \
                   len(self.finished), len(self.retired))        

    def round(self):
        """ 
        One round of parcor.

        """

        """    
        Step 1.  running -> finished

        Move jobs from the running to finished sets
        by determining if they are done

        """
        new_finished = set([])
        new_waiting = set([])
        for job in self.running:
            try:
                if job.is_finished():
                    self.dprint ("job finished: " + (str(job)))
                    new_finished.add(job)
            except RuntimeError:
                self.dprint ( "job finished with bad error code: " + (str(job)))
                job.prob *= 0.95
                self.dprint ( "re-waiting with prob = %.3f" % job.prob )
                new_waiting.add(job)
        self.waiting = self.waiting | new_waiting
        self.running = self.running - new_finished - new_waiting
        self.finished = self.finished | new_finished
        self.dprint ("step running->finished complete.")
        self.status()
                     
        """

        Step 2. finished -> new_waiting
        
        Consult finished set and construct new jobs if warranted.
        This may or may not result in adding things to the waiting set,
        Note that, if new jobs are added to waiting, we must remove
        the finished jobs that gave rise to them.

        new_waiting is new jobs to be added to waiting set to be started
        consumed_finished_jobs are jobs from finished which were used to construct 
        new_waiting and thus need to be discarded from finished

        """
        (new_waiting, consumed_finished) = self.create_new()        
        if new_waiting is None:
            print "No new_waiting created"
        else:
            print "Created new_waiting"
            self.finished = self.finished - consumed_finished
            self.retired = self.retired | consumed_finished
            self.waiting.add(new_waiting)
        self.dprint("step finished->new_waiting complete")
        self.status()

        """
        
        Step 3. Fill the cores.  

        That is, figure out how many cores are 
        idle and hand them waiting jobs
        """
        # number of occupied cores
        num_cores_running = len(self.running)
        # n this is how many jobs we are allowed to start        
        if num_cores_running >= self.max_jobs:
            n = 0
        else:
            n = self.max_jobs - num_cores_running
        # but we can only start as many jobs as are waiting
        n = min(n, len(self.waiting))
        new_running = []
        self.dprint ("starting %d jobs" % (len(new_running)))
        while n > 0:
            for potential in self.waiting:
                if (not (potential in new_running)) and (random.random() < potential.prob):
                    m = memory()
                    if m['free'] < potential.mem_required:
                        print "only %d memory free.  can't start any more jobs" % (m['free'])
                        n = 0
                        break
                        
                    potential.start()
                    new_running.append(potential)
                    n = n - 1                    
                    break
        for job in new_running:
            self.dprint ("started job: " + (str(job)))
        self.waiting = self.waiting - set(new_running)
        self.running = self.running | set(new_running)
        self.dprint ("step fill cores complete.")
        self.status()


    def run(self):
        """
        Run this assemblage of parcor jobs
        """
        
        start_time = time.time()
        while True:
            self.dprint("-----------------------")
            dt = time.time() - start_time
            self.dprint("parcor round %d %.2f sec elapsed" % (self.roundnum, dt))
            # one round of parcor
            self.round()
            # check for done
            if (len(self.running) == 0) and (len(self.waiting) == 0):
                self.dprint ( "no jobs waiting -- done" )
                break
            time.sleep(5)
            self.roundnum += 1

    def create_new(self):
        """
        Creates new waiting jobs, if possible.
        Examine finished set and generate new work.
        The idea here is that this allows you to build 
        "if this finished then start this" or
        "if this and this finished, combine with this job" logic. 
        Must return a pair of sets
        (new_waiting, consumed_finished_jobs)
        To be defined in subclass
        """
        return (None, set([]))



