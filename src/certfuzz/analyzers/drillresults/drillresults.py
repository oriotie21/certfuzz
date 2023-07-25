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
Created on Jan 29, 2016

@author: adh
'''
import logging
from certfuzz.analyzers.analyzer_base import Analyzer
from certfuzz.analyzers.drillresults.testcasebundle_base import TestCaseBundle
from certfuzz.drillresults.errors import TestCaseBundleError
from certfuzz.analyzers.drillresults.testcasebundle_linux import LinuxTestCaseBundle
from certfuzz.analyzers.drillresults.testcasebundle_darwin import DarwinTestCaseBundle
from certfuzz.analyzers.drillresults.testcasebundle_windows import WindowsTestCaseBundle

logger = logging.getLogger(__name__)

OUTFILE_EXT = "drillresults"
get_file = lambda x: '{}.{}'.format(x, OUTFILE_EXT)

class DrillResults(Analyzer):
    '''
    Drills a bit deeper into results to see how exploitable a testcase might be.
    '''
    _tcb_cls = TestCaseBundle

    def __init__(self, cfg, testcase):
        '''
        Constructor
        '''
        self.cfg = cfg
        self.testcase = testcase

        self.outfile = get_file(self.testcase.fuzzedfile.path)
        self.output_lines = []

        # TODO: This should be dynamic, no?
        self.ignore_jit = False

    def _process_tcb(self, tcb):
        details = tcb.details
        score = tcb.score
        crash_key = tcb.crash_hash

        output_lines = []

        output_lines.append(
            '%s - Exploitability rank: %s' % (crash_key, score))
        output_lines.append('Fuzzed file: %s' % details['fuzzedfile'])

        for exception in details['exceptions']:
            shortdesc = details['exceptions'][exception]['shortdesc']
            eiftext = ''
            efa = '0x' + details['exceptions'][exception]['efa']
            if details['exceptions'][exception]['EIF']:
                eiftext = " *** Byte pattern is in fuzzed file! ***"
            output_lines.append(
                'exception %s: %s accessing %s  %s' % (exception, shortdesc, efa, eiftext))
            if details['exceptions'][exception]['instructionline']:
                output_lines.append(
                    details['exceptions'][exception]['instructionline'])
            module = details['exceptions'][exception]['pcmodule']
            if module == 'unloaded':
                if not self.ignore_jit:
                    output_lines.append(
                        'Instruction pointer is not in a loaded module!')
            else:
                output_lines.append('Code executing in: %s' % module)

        self.output_lines = output_lines

    def _write_outfile(self): 
        with open(self.outfile, 'w') as f:
            f.write('\n'.join(self.output_lines))

    def go(self):
        # turn testcase into tescase_bundle
        # Get crash details for first exception
        with self._tcb_cls(cfg=self.cfg, dbg_outfile=self.testcase.dbg_files[0],
                           testcase_file=self.testcase.fuzzedfile.path,
                           crash_hash=self.testcase.signature,
                           ignore_jit=False) as tcb:
            try:
                tcb.go()
            except TestCaseBundleError as e:
                logger.warning(
                    'Skipping drillresults on testcase %s: %s', self.testcase.signature, e)
                return

            # Get temporary testase bundle for exceptions beyond the first
            # Update tcb with those exceptions, updating cumulative score
            # On any platform other that Windows, this is a no-op
            for index, exception in enumerate(self.testcase.dbg_files):
                if exception > 0:
                    with self._tcb_cls(cfg=self.cfg, dbg_outfile=self.testcase.dbg_files[exception],
                                       testcase_file=self.testcase.fuzzedfile.path,
                                       crash_hash=self.testcase.signature,
                                       ignore_jit=False) as temp_tcb:
                        try:
                            temp_tcb.go()
                        except TestCaseBundleError as e:
                            logger.warning(
                                'Skipping drillresults on testcase %s: %s', self.testcase.signature, e)
                            continue

                        tcb.details['exceptions'].update(
                            temp_tcb.details['exceptions'])

                        tcb.score = min(tcb.score, temp_tcb.score)

        self._process_tcb(tcb)
        self._write_outfile()
        # if score < max_score do something (more interesting)
        # if score > max_score do something else (less interesting)

class LinuxDrillResults(DrillResults):
    _tcb_cls = LinuxTestCaseBundle

class DarwinDrillResults(DrillResults):
    _tcb_cls = DarwinTestCaseBundle

class WindowsDrillResults(DrillResults):
    _tcb_cls = WindowsTestCaseBundle
