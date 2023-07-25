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
Created on Feb 27, 2012

@author: adh
'''
import logging
import random

from certfuzz.debuggers import allowed_exploitability_values, register
from certfuzz.helpers.misc import random_str

from . import Debugger

# import things needed to inject randomness
logger = logging.getLogger(__name__)

def factory(*args):
    return NullDebugger(*args)

class NullDebugger(Debugger):
    '''
    classdocs
    '''

    def debug(self, *args, **kwargs):
        logger.debug('Args: %s', args)
        logger.debug('KwArgs: %s', kwargs)
        # Flip a coin for whether this is a crash
        self.result['debug_crash'] = bool(random.randint(0, 1))
        # append a random string so we'll limit duplicates
        self.result['crash_hash'] = 'fake_crash_%s' % random_str(len=1)

        # pick a random exploitability value
        self.result['exp'] = random.choice(allowed_exploitability_values)
        self.debugger_output = 'How many bugs would a debugger debug if a debugger could debug bugs?'
        self.type = 'fake'
        self.seedfile = 'seedfile'
        self.seed = 'seed'
        self.faddr = 'faddr'
        # Flip a coin for heisenbuggery
        self.is_heisenbug = bool(random.randint(0, 1))
        return self.result

register(NullDebugger)
