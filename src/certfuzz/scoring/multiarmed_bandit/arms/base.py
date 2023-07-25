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

from certfuzz.scoring.multiarmed_bandit.arms.errors import BanditArmError

logger = logging.getLogger(__name__)

class BanditArmBase(object):
    '''
    Base class for multi-armed bandit arms. The base class simply counts
    successes and trials, and maintains a constant probability of 1.0.
    '''
    def __init__(self):
        self.successes = 0
        self.trials = 0
        self.probability = None

        # initialize probability
        self.update()

    @property
    def failures(self):
        return self.trials - self.successes

    def __repr__(self):
        return '%s' % self.__dict__

    def update(self, successes=0, trials=0):
        '''
        Update total successes and trials, recalculate probability
        :param successes:
        :param trials:
        '''
        self.successes += successes
        self.trials += trials
        self._update_p(successes, trials)
        if self.probability is None:
            logger.debug("MAB arm: %s", self)
            raise BanditArmError('probability not set')
        elif not (0.0 <= self.probability <= 1.0):
            logger.debug("MAB arm: %s", self)
            raise BanditArmError('probability must be between 0.0 <= {:f} <= 1.0'.format(self.probability))

    def _update_p(self, *_unused_args):
        '''
        Internal method, ensure that self.probability gets assigned
        :param successes:
        :param trials:
        '''
        # implement a naive arm that maintains constant probability
        self.probability = 1.0

    def doubt(self):
        '''
        Inject doubt into the calculation by reducing trials to
        trials/successes and successes -> 1. This essentially means that you'll
        still have the same probability, but will introduce variation into the
        probability going forward if current reality has changed from the set
        you were trained under.
        '''
        if self.successes > 0:
            scaled_trials = int(float(self.trials) / float(self.successes))
            # make sure trials is at least 1
            self.trials = max(scaled_trials, 1)
            self.successes = 1
            self.update()

    def forget(self):
        '''
        Resets successes and trials to zero, then updates probability.
        '''
        self.successes = 0
        self.trials = 0
        self.update()
