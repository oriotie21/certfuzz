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
Created on Feb 22, 2013

@organization: cert.org
'''
import logging

from certfuzz.scoring.multiarmed_bandit.errors import MultiArmedBanditError
from certfuzz.scoring.multiarmed_bandit.arms.base import BanditArmBase

logger = logging.getLogger(__name__)

class MultiArmedBanditBase(object):
    '''
    Implements a simple round robin iterator
    '''
    arm_type = BanditArmBase

    def __init__(self):
        self.things = {}
        self.arms = {}

    def arms_as_dict(self):
        return {k: dict(arm.__dict__) for k, arm in self.arms.iteritems()}

    def add_item(self, key=None, obj=None):

        if key is None:
            raise MultiArmedBanditError('unspecified key for arm')
        if obj is None:
            raise MultiArmedBanditError('unspecified value for arm')
        logger.debug('Creating arm %s', key)
        self.things[key] = obj
        # create a new arm of the desired type
        new_arm = self.arm_type()

        # set the new arm's params based on the results we've already found
        new_arm.successes = self.successes
        new_arm.trials = self.trials

        # but don't trust those averages too strongly
        new_arm.doubt()

        # add the new arm to the set
        self.arms[key] = new_arm

    def del_item(self, key=None):
        if key is None:
            return

        for d in (self.things, self.arms):
            try:
                del(d[key])
            except KeyError:
                # if there was a keyerror, our job is already done
                pass

    def record_result(self, key, successes=0, trials=0):
        logger.debug(
            'Recording result: key=%s successes=%d trials=%d', key, successes, trials)
        arm = self.arms[key]
        arm.update(successes, trials)

    def record_tries(self, key=None, tries=1):
        self.record_result(key, successes=0, trials=tries)

    def _log_arm_p(self):
        logger.debug('Updated probabilities')
        for k, v in self.arms.iteritems():
            logger.debug('key=%s probability=%f', k, v.probability)

    def record_success(self, key=None, successes=1):
        self.record_result(key, successes, trials=0)
        self._log_arm_p()

    @property
    def successes(self):
        return sum([a.successes for a in self.arms.values()])

    @property
    def trials(self):
        return sum([a.trials for a in self.arms.values()])

    @property
    def _total_p(self):
        return sum([a.probability for a in self.arms.itervalues()])

    @property
    def mean_p(self):
        return self._total_p / len(self.arms)

    @property
    def mean_p_with_trials(self):
        total = 0.0
        count = 0

        for a in self.arms.itervalues():
            if not a.trials:
                continue
            total += a.probability
            count += 1
        return float(total) / count

    def __iter__(self):
        return self

    def next(self):
        raise StopIteration()
