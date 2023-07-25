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
Created on Jul 16, 2014

@organization: cert.org
'''
import logging
import os

from certfuzz.minimizer.win_minimizer import WindowsMinimizer
from certfuzz.tc_pipeline.tc_pipeline_base import TestCasePipelineBase
from certfuzz.reporters.copy_files import CopyFilesReporter
from certfuzz.analyzers.stderr import StdErr
from certfuzz.analyzers.cdbanalyze import CdbAnalyze
from certfuzz.analyzers.drillresults import WindowsDrillResults

logger = logging.getLogger(__name__)

class WindowsTestCasePipeline(TestCasePipelineBase):
    _minimizer_cls = WindowsMinimizer

    def _setup_analyzers(self):
        # self.analyzer_classes.append(StdErr)
        self.analyzer_classes.append(CdbAnalyze)
        self.analyzer_classes.append(WindowsDrillResults)

    def _pre_verify(self, testcase):
        # pretty-print the testcase for debugging
        logger.debug('Testcase:')
        from pprint import pformat
        formatted = pformat(testcase.__dict__)
        for line in formatted.splitlines():
            logger.debug('... %s', line.rstrip())

    def _verify(self, testcase):
        keep_it, reason = self.keep_testcase(testcase)

        if not keep_it:
            if self.options['null_runner'] and reason == 'not a crash':
                # Don't be too chatty about rejecting a null runner crash
                pass
            else:
                logger.info('Candidate testcase rejected: %s', reason)
            testcase.should_proceed_with_analysis = False
            return

        logger.debug('Keeping testcase (reason=%s)', reason)
        testcase.should_proceed_with_analysis = True
        logger.info("Crash confirmed: %s Exploitability: %s Faulting Address: %s",
                    testcase.crash_hash, testcase.exp, testcase.faddr)
        self.success = True

    def _report(self, testcase):
        with CopyFilesReporter(testcase, keep_duplicates=self.options['keep_duplicates']) as reporter:
            reporter.go()

    def keep_testcase(self, testcase):
        '''Given a testcase, decide whether it is a keeper. Returns a tuple
        containing a boolean indicating whether to keep the testcase, and
        a string containing the reason for the boolean result.
        @param testcase: a testcase object
        @return (bool,str)
        '''
        if testcase.is_crash:
            if self.options['keep_duplicates']:
                return (True, 'keep duplicates')
            elif self.uniq_func(testcase.signature):
                # Check if crasher directory exists already
                target_dir = testcase._get_output_dir(self.outdir)
                if os.path.exists(target_dir):
                    if len(os.listdir(target_dir)) > 0:
                        return (False, 'skip duplicate %s' % testcase.signature)
                    else:
                        return(True, 'Empty output directory')
                else:
                    return (True, 'unique')
            else:
                return (False, 'skip duplicate %s' % testcase.signature)
        elif self.options['null_runner']:
            return (False, 'not a crash')
        elif self.options['keep_heisenbugs']:
            target_dir = testcase._get_output_dir(self.outdir)
            return (True, 'heisenbug')
        else:
            return (False, 'skip heisenbugs')
