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
Created on Jan 12, 2016

@author: adh
'''
import logging
import os
import shutil

from distutils.dir_util import copy_tree

from certfuzz.fuzztools import filetools
from certfuzz.reporters.errors import ReporterError
from certfuzz.reporters.reporter_base import ReporterBase

logger = logging.getLogger(__name__)

class CopyFilesReporter(ReporterBase):
    '''
    Copies files to a location
    '''

    def __init__(self, testcase, keep_duplicates=False):
        '''
        Constructor
        '''
        ReporterBase.__init__(self, testcase)

        self.target_dir = testcase.target_dir
        self.keep_duplicates = keep_duplicates

    def go(self):
        dst_dir = self.target_dir
        if len(dst_dir) > 130:
            # Don't make a path too deep.  Windows won't support it
            dst_dir = dst_dir[:130] + '__'
        # ensure target dir exists already (it might because of crash logging)
        filetools.mkdir_p(dst_dir)
        if (len(os.listdir(dst_dir)) > 0 and not self.keep_duplicates):
            logger.debug(
                'Output path %s already contains output. Skipping.' % dst_dir)
            return

        src_dir = self.testcase.tempdir
        if not os.path.exists(src_dir):
            raise ReporterError('Testcase tempdir not found: %s', src_dir)

        src_paths = [os.path.join(src_dir, f) for f in os.listdir(src_dir)]

        for f in src_paths:
            logger.debug('Copy %s -> %s', f, dst_dir)
	    if(os.path.isdir(f)):
            	copy_tree(f, dst_dir)
            else:
                shutil.copy2(f, dst_dir)
