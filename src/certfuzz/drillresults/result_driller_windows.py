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
This script looks for interesting crashes and rate them by potential exploitability
'''
import logging
import os
import re

from certfuzz.analyzers.drillresults.testcasebundle_windows import WindowsTestCaseBundle as TestCaseBundle
from certfuzz.drillresults.result_driller_base import ResultDriller
from certfuzz.drillresults.errors import TestCaseBundleError

logger = logging.getLogger(__name__)

regex = {
    'first_msec': re.compile('^sf_.+-\w+-0x.+.-[A-Z]+.+e0.+'),
}

class WindowsResultDriller(ResultDriller):

    def _platform_find_testcases(self, crash_dir, files, root, force=False):
        if "0x" in crash_dir or 'BFF_testcase' in crash_dir:
            # Create dictionary for hashes in results dictionary
            hash_dict = {}
            hash_dict['hash'] = crash_dir
            crasherfile = ''

            # Check each of the files in the hash directory
            for current_file in files:
                # if regex['first_msec'].match(current_file):
                if current_file.endswith('.msec') and '.e0.' in current_file:
                    # If it's exception #0, strip out the exploitability part of
                    # the file name. This gives us the crasher file name
                    crasherfile, _junk = os.path.splitext(current_file)
                    crasherfile = crasherfile.replace('-EXP', '')
                    crasherfile = crasherfile.replace('-PEX', '')
                    crasherfile = crasherfile.replace('-PNE', '')
                    crasherfile = crasherfile.replace('-UNK', '')
                    crasherfile = crasherfile.replace('.e0', '')
                elif current_file.endswith('.drillresults') and not force:
                    # If we have a drillresults file for this crash hash, we use
                    # that output instead of recalculating it
                    # Use the .drillresults output for this crash hash
                    self._load_dr_output(crash_dir,
                                         os.path.join(root, current_file))

            for current_file in files:
                if crash_dir in self.dr_scores:
                    # We are currently working with a crash hash
                    if self.dr_scores[crash_dir] is not None:
                        # We've already got a score for this crash_dir
                        logger.debug('Skipping %s' % current_file)
                        continue

                # Go through all of the .msec files and parse them
                if current_file.endswith('.msec'):
                    dbg_file = os.path.join(root, current_file)
                    if crasherfile and root not in crasherfile:
                        crasherfile = os.path.join(root, crasherfile)
                    with TestCaseBundle(dbg_file, crasherfile, crash_dir,
                                        self.ignore_jit) as tcb:
                        try:
                            tcb.go()
                        except TestCaseBundleError:
                            # Nothing useful in this msec file
                            continue

                        _updated_existing = False
                        # if not self.testcase_bundles:
                        #    continue
                        for index, tcbundle in enumerate(self.testcase_bundles):
                            if tcbundle.crash_hash == crash_dir:
                                # This is a new exception for the same crash
                                # hash
                                self.testcase_bundles[index].details[
                                    'exceptions'].update(tcb.details['exceptions'])
                                # If the current exception score is lower than
                                # the existing crash_dir score, update it
                                self.testcase_bundles[index].score = min(
                                    self.testcase_bundles[index].score, tcb.score)
                                _updated_existing = True
                        if not _updated_existing:
                            # This is a new crash hash
                            self.testcase_bundles.append(tcb)
