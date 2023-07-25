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
Created on Mar 14, 2012

@author: adh
'''
import logging

from certfuzz.debuggers.output_parsers.debugger_file_base import DebuggerFile

logger = logging.getLogger(__name__)

required_checks = ['crash_hash', 'exploitability']

class MsecFile(DebuggerFile):
    '''
    classdocs
    '''
    _key = 'msec'

    def __init__(self, *args, **kwargs):
        self.crash_hash = None
        self.exp = None
        self.faddr = None
        self.secondchance = False

        # add our callbacks
        self.line_callbacks = [
                               self._find_exploitability,
                               self._find_efa,
                               self._find_hash,
                               self._find_secondchance,
                               ]

        self.passed = set()
        # initialize our parent class
        DebuggerFile.__init__(self, *args, **kwargs)

        # override the default from DebuggerFile
        self.is_crash = False

        required_checks = ['crash_hash', 'exploitability']
        checks_passed = [x in self.passed for x in required_checks]
        self.is_crash = all(checks_passed)

#        if self.lines:
#            self.debugger_output = '\n'.join(self.lines)

    def _process_backtrace(self):
        pass

    def _hashable_backtrace(self):
        pass

    def get_testcase_signature(self, backtrace_level):
        return self.crash_hash

    def _find_exploitability(self, line):
        if line.startswith('Exploitability Classification'):
            exploitability = self.split_and_strip(line)

            # Count it as a crash as long as it has a classification
            if exploitability and exploitability != 'NOT_AN_EXCEPTION':
                self.passed.add('exploitability')

            self.exp = exploitability
            self.line_callbacks.remove(self._find_exploitability)

    def _find_efa(self, line):
        if line.startswith('Exception Faulting Address'):
            efa = self.split_and_strip(line)
            # turn it into a properly formatted string
            self.faddr = '0x%08x' % int(efa, 16)
            self.line_callbacks.remove(self._find_efa)

    def _find_hash(self, line):
        if line.startswith('Exception Hash'):
            crash_hash = self.split_and_strip(line)
            # count it as a crash as long as it has a hash
            if crash_hash:
                self.passed.add('crash_hash')

            self.crash_hash = crash_hash
            self.line_callbacks.remove(self._find_hash)

    def _find_secondchance(self, line):
        if '!!! second chance !!!' in line:
            self.secondchance = True
            self.line_callbacks.remove(self._find_secondchance)

    def split_and_strip(self, line, delim=':'):
        '''
        Return the second half of the line after the delimiter, stripped of
        whitespace
        @param line:
        @param delim: defaults to ":"
        '''
        return line.split(delim)[1].strip()
