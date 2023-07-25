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
Created on Aug 5, 2011

@organization: cert.org
'''
import platform
import os.path
from certfuzz.analyzers.analyzer_base import Analyzer

_platforms = ['Windows']
_platform_is_supported = platform.system() in _platforms

OUTFILE_EXT = "analyze"
get_file = lambda x: '%s.%s' % (x, OUTFILE_EXT)

class CdbAnalyze(Analyzer):
    '''
    classdocs
    '''

    def __init__(self, cfg, testcase):
        '''
        Constructor
        '''
        if not _platform_is_supported:
            return None

        self.outfile = get_file(testcase.fuzzedfile.path)
        # !analyze takes longer to complete than !exploitable. Give it 2x the time
        self.timeout = cfg['runner']['runtimeout'] * 2
        self.watchcpu = cfg['runner']['watchcpu']

        Analyzer.__init__(self, cfg, testcase, self.outfile, self.timeout)

    def go(self):
        if not _platform_is_supported:
            return None

        prg = self.cmdargs[0]
        args = self.cmdargs[1:]

        from ..debuggers.msec import MsecDebugger
        MsecDebugger(
            program=prg, cmd_args=args, outfile_base=self.outfile, timeout=self.timeout, watchcpu=self.watchcpu, exception_depth=0, debug_heap=self.cfg['debugger']['debugheap'], cdb_command='!analyze -v').go()
