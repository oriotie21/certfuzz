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

from certfuzz.analyzers.drillresults.testcasebundle_darwin import DarwinTestCaseBundle as TestCaseBundle
from certfuzz.drillresults.result_driller_base import ResultDriller

logger = logging.getLogger(__name__)

class DarwinResultDriller(ResultDriller):

    def _platform_find_testcases(self, crash_hash, files, root, force=False):
        # Only use directories that are hashes
        # if "0x" in crash_hash:
        # Create dictionary for hashes in results dictionary
        crasherfile = ''
        # Check each of the files in the hash directory

        for current_file in files:
            # Look for a .drillresults file first.  If there is one, we get the
            # drillresults info from there and move on.
            if current_file.endswith('.drillresults') and not force:
                # Use the .drillresults output for this crash hash
                self._load_dr_output(crash_hash,
                                     os.path.join(root, current_file))
                # Move on to next file
                continue

        for current_file in files:

            if crash_hash in self.dr_scores:
                # We are currently working with a crash hash
                if self.dr_scores[crash_hash] is not None:
                    # We've already got a score for this crash_hash
                    continue

            # Go through all of the .cw files and parse them
            if current_file.endswith('.cw'):
                dbg_file = os.path.join(root, current_file)
                logger.debug('found CrashWrangler file: %s', dbg_file)
                crasherfile = dbg_file.replace('.gmalloc', '')
                crasherfile = crasherfile.replace('.cw', '')
                with TestCaseBundle(dbg_file, crasherfile, crash_hash,
                                    self.ignore_jit) as tcb:
                    tcb.go()
                    self.testcase_bundles.append(tcb)
