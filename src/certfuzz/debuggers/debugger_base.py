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
Created on Oct 23, 2012

@organization: cert.org
'''
import logging

from certfuzz.debuggers.errors import DebuggerError

logger = logging.getLogger(__name__)

result_fields = 'debug_crash crash_hash exp faddr output dbg_type'.split()
allowed_exploitability_values = ['UNKNOWN', 'PROBABLY_NOT_EXPLOITABLE',
                                 'PROBABLY_EXPLOITABLE', 'EXPLOITABLE']

class Debugger(object):
    '''
    classdocs
    '''
    _platform = None
    _key = 'debugger'
    _ext = 'debug'

    def __init__(self, program=None, cmd_args=None, outfile_base=None, timeout=None, **options):
        '''
        Default initializer for the base Debugger class.
        '''
        logger.debug('Initialize Debugger')
        self.program = program
        self.cmd_args = cmd_args
        self.outfile = '.'.join((outfile_base, self._ext))
        self.timeout = timeout
        self.input_file = ''
        self.debugger_output = None
        self.result = {}
        self._reset_result()
        self.seed = None
        self.faddr = None
        self.type = self._key
        self.debugger_output = ''
        self.debugheap = False
        logger.debug('DBG OPTS %s', options)

        # turn any other remaining options into attributes
        self.__dict__.update(options)
        logger.debug('DEBUGGER: %s', self.__dict__)

    def _reset_result(self):
        for key in result_fields:
            self.result[key] = None

    def _validate_exploitability(self):
        if not self.result['exp'] in allowed_exploitability_values:
            raise DebuggerError(
                'Unknown exploitability value: %s' % self.result['exp'])

    def outfile_basename(self, basename):
        return '.'.join((basename, self.type))

    def write_output(self, target=None):
        if not target:
            target = self.outfile

        with open(target, 'w') as fd:
            fd.write(self.debugger_output)

    def carve(self, string, token1, token2):
        raise NotImplementedError

    def kill(self, pid, returncode):
        raise NotImplementedError

    def debug(self, input_filename):
        raise NotImplementedError

    def go(self):
        raise NotImplementedError

    def debugger_app(self):
        '''
        Returns the name of the debugger application to use in this class
        '''
        raise NotImplementedError

    def debugger_test(self):
        '''
        Returns a command line (as list) that can be run via subprocess.call
        to confirm whether the debugger is on the path.
        '''
        raise NotImplementedError

    def __enter__(self):
        return self

    def __exit__(self, etype, value, traceback):
        pass

    @property
    def extension(self):
        return self._ext
