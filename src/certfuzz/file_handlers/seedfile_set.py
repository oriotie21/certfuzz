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
Created on Apr 12, 2011

@organization: cert.org
'''
import logging
import os

from certfuzz.file_handlers.directory import Directory
from certfuzz.file_handlers.errors import SeedFileError, SeedfileSetError
from certfuzz.file_handlers.seedfile import SeedFile
from certfuzz.fuzztools import filetools

# Using a generic name here so we can easily swap out other MAB
# implementations if we want to
from certfuzz.scoring.multiarmed_bandit.bayesian_bandit import BayesianMultiArmedBandit as MultiArmedBandit

logger = logging.getLogger(__name__)

class SeedfileSet(MultiArmedBandit):
    '''
    classdocs
    '''

    def __init__(self, campaign_id=None, originpath=None, localpath=None,
                 outputpath='.', child=None, logfile=None):
        '''
        Constructor
        '''
        MultiArmedBandit.__init__(self)
#         self.campaign_id = campaign_id
        self.seedfile_output_base_dir = outputpath

        self.originpath = originpath
        self.localpath = localpath
        # TODO: merge self.outputpath with self.seedfile_output_base_dir
        self.outputpath = outputpath

        self.origindir = None
        self.localdir = None
        self.outputdir = None
        self.child = child

        if logfile:
            hdlr = logging.FileHandler(logfile)
            logger.addHandler(hdlr)

        logger.debug(
            'SeedfileSet output_dir: %s', self.seedfile_output_base_dir)

    def __enter__(self):
        self._setup()
        return self

    def __exit__(self, etype, value, traceback):
        pass

    def _setup(self):
        self._set_directories()
        self._copy_files_to_localdir()
        self._add_local_files_to_set()

    def _set_directories(self):
        if self.originpath:
            self.origindir = Directory(self.originpath, self.child)
        if self.localpath:
            self.localdir = Directory(self.localpath, self.child, create=True)
        if self.outputpath:
            self.outputdir = Directory(self.outputpath, self.child, create=True)

    def _copy_files_to_localdir(self):
        for f in self.origindir:
            self.copy_file_from_origin(f)

    def _add_local_files_to_set(self):
        self.localdir.refresh()
        files_to_add = [f.path for f in self.localdir]
        self.add_file(*files_to_add)

    def add_file(self, *files):
        for f in files:
            try:
                seedfile = SeedFile(self.seedfile_output_base_dir, f, self.child)
            except SeedFileError:
                logger.warning('Skipping empty file %s', f)
                continue
            logger.info('Adding file to set: %s', seedfile.path)
            self.add_item(seedfile.md5, seedfile)

    def remove_file(self, seedfile):
        logger.info('Removing file from set: %s', seedfile.basename)
        self.del_item(seedfile.md5)

    def copy_file_from_origin(self, f):
        

        if (os.path.basename(f.path) == '.DS_Store'):
            return 0

        # convert the local filenames from <foo>.<ext> to <md5>.<ext>
        basename = 'sf_' + f.md5 + f.ext
        targets = [os.path.join(d, basename)
                   for d in (self.localpath, self.outputpath)]
        
        filetools.copy_file(f.path, *targets)
        for target in targets:
            filetools.make_writable(target)

    def paths(self):
        for x in self.things.values():
            yield x.path

    def next_item(self):
        '''
        Returns a seedfile object selected per the scorable_set object.
        Verifies that the seedfile exists, and removes any nonexistent
        seedfiles from the set
        '''
        if not len(self.things):
            raise SeedfileSetError

        while len(self.things):
            logger.debug('Thing count: %d', len(self.things))
            # continue until we find one that exists, or else the set is empty
            sf = MultiArmedBandit.next(self)
            if sf.exists():
                # it's still there, proceed
                return sf
            else:
                # it doesn't exist, remove it from the set
                logger.warning(
                    'Seedfile no longer exists, removing from set: %s', sf.path)
                self.del_item(sf.md5)
