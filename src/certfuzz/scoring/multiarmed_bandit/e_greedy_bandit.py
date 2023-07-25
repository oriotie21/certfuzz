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
Created on Jan 7, 2014

@organization: cert.org
'''
from certfuzz.scoring.multiarmed_bandit.multiarmed_bandit_base import MultiArmedBanditBase
from certfuzz.scoring.multiarmed_bandit.arms.bayes_laplace import BanditArmBayesLaplace
from certfuzz.scoring.multiarmed_bandit.errors import MultiArmedBanditError

import random

class EpsilonGreedyMultiArmedBandit(MultiArmedBanditBase):
    '''
    Returns a random thing from its collection based on the Epsilon-Greedy MultiArmed Bandit strategy
    http://en.wikipedia.org/wiki/Multi-armed_bandit
    '''
    arm_type = BanditArmBayesLaplace

    def __init__(self, epsilon=0.1):
        '''
        :param epsilon: fraction of time spent exploring (vs. exploiting the best performer)
        '''
        MultiArmedBanditBase.__init__(self)
        if not 0.0 < epsilon < 1.0:
            raise MultiArmedBanditError('epsilon must be between 0.0 and 1.0')

        self.e = epsilon

    def _max_keys(self):
        max_p = 0.0
        _maybe_max_k = []
        for key, arm in self.arms.iteritems():
            if arm.probability >= max_p:
                max_p = arm.probability
                _maybe_max_k.append((key, max_p))

        # now we have a list of tuples, but the early ones might be less than max.
        # since we went through them all on the way here though we know that max_p is
        # the actual max, so all we need to do is test for that on each tuple
        max_keys = [k for (k, p) in _maybe_max_k if p == max_p]

        return max_keys

    def _all_except(self, klist):
        return [k for k in self.things.iterkeys() if not k in klist]

    def _next_key(self):
        _max = self._max_keys()
        if random.random() <= 1.0 - self.e:
            return random.choice(_max)
        else:
            return random.choice(self._all_except(_max))

    def next(self):
        '''
        With probability 1-self.e, choose the best performer. Otherwise choose one of the others with equal probability
        '''
        return self.things[self._next_key()]
