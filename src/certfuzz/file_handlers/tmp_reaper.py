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
Created on Apr 21, 2011

@organization: cert.org
'''
import logging
import os
import platform
import shutil
import tempfile

from certfuzz.fuzztools.filetools import delete_contents_of
from certfuzz.file_handlers.watchdog_file import touch_watchdog_file

logger = logging.getLogger(__name__)

class TmpReaper(object):
    '''
    classdocs
    '''

    def __init__(self):
        '''
        Constructor
        '''
        logger.debug('Reaping tmp...')
        self.tmp_dir = tempfile.gettempdir()
        if platform.system() == 'Windows':
            self.clean_tmp = self.clean_tmp_windows
        else:
            self.clean_tmp = self.clean_tmp_unix

    def clean_tmp_windows(self, extras=[]):
        '''
        Removes as many of the contents of tmpdir as possible. Logs skipped
        files but otherwise won't block on the failure to delete something.
        '''
        paths_to_clear = set(extras)
        paths_to_clear.add(self.tmp_dir)
        skipped = delete_contents_of(paths_to_clear)
        for (skipped_item, reason) in skipped:
            logger.debug('Failed to delete %s: %s', skipped_item, reason)

    def clean_tmp_unix(self, extras=[]):
        '''
        Starts at the top level of tmpdir and deletes files, directories
        and symlinks owned by the same uid as the current process.
        '''
        my_uid = os.getuid()

        for basename in os.listdir(self.tmp_dir):
            path = os.path.join(self.tmp_dir, basename)
            try:
                if os.path.islink(path):
                    path_uid = os.lstat(path).st_uid
                else:
                    path_uid = os.stat(path).st_uid
                if my_uid == path_uid:
                    if os.path.isfile(path):
                        os.remove(path)
                    elif os.path.islink(path):
                        os.unlink(path)
                    elif os.path.isdir(path):
                        shutil.rmtree(path)
            except (IOError, OSError):
                # we don't mind these exceptions as they're usually indicative
                # of a file that got deleted before we could do the same
                continue
        # We've just cleaned tmp, which is the default watchdog file location
        # If BFF dies before the watchdog file is recreated, UbuFuzz won't
        # notice
        touch_watchdog_file()
