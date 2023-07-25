### BEGIN LICENSE ###
### Use of the CERT Basic Fuzzing Framework (BFF) and related source code is
### subject to the following terms:
### 
### # LICENSE #
### 
### Copyright (C) 2010-2016 Carnegie Mellon University. All Rights Reserved.
### 
### Redistribution and use in source and binary forms, with or without
### modification, are permitted provided that the following conditions are met:
### 
### 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following acknowledgments and disclaimers.
### 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following acknowledgments and disclaimers in the documentation and/or other materials provided with the distribution.
### 3. Products derived from this software may not include "Carnegie Mellon University," "SEI" and/or "Software Engineering Institute" in the name of such derived product, nor shall "Carnegie Mellon University," "SEI" and/or "Software Engineering Institute" be used to endorse or promote products derived from this software without prior written permission. For written permission, please contact permission@sei.cmu.edu.
### 
### # ACKNOWLEDGMENTS AND DISCLAIMERS: #
### Copyright (C) 2010-2016 Carnegie Mellon University
### 
### This material is based upon work funded and supported by the Department of
### Homeland Security under Contract No. FA8721-05-C-0003 with Carnegie Mellon
### University for the operation of the Software Engineering Institute, a federally
### funded research and development center.
### 
### Any opinions, findings and conclusions or recommendations expressed in this
### material are those of the author(s) and do not necessarily reflect the views of
### the United States Departments of Defense or Homeland Security.
### 
### NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE
### MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO
### WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER
### INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR
### MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL.
### CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT
### TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
### 
### This material has been approved for public release and unlimited distribution.
### 
### CERT(R) is a registered mark of Carnegie Mellon University.
### 
### DM-0000736
### END LICENSE ###

'''
Created on Jan 3, 2014

@author: adh
'''
import time

class StateTimer(object):
    '''
    Implements a timer with multiple states
    '''
    def __init__(self, states=None):
        self.current_state = None
        self.timers = {}
        self._in = None
        self._delim = ', '

    def __str__(self):
        return 'State Timer - ' + self._delim.join('{}: {}'.format(k, v) for k, v in self.timers.iteritems())

    def _reset(self):
        self.current_state = None
        self._in = None

    def states(self):
        return self.timers.keys()

    def enter_state(self, new_state=None):
        if new_state == self.current_state:
            # nothing to do
            return
        # state change
        # close out current timer
        if self.current_state is not None:
            _out = time.time()
            _elapsed = _out - self._in
            self.timers[self.current_state] += _elapsed

        # start new timer
        if new_state is None:
            self._reset()
        else:
            self.current_state = new_state
            self._in = time.time()
            if not self.current_state in self.timers:
                self.timers[self.current_state] = 0.0

    def total_time(self):
        return sum(self.timers.itervalues())

    def time_in(self, state):
        if state in self.timers:
            return self.timers[state]
        else:
            return 0.0

STATE_TIMER = StateTimer()
