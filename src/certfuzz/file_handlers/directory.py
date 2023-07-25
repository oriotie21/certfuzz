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
Created on Mar 18, 2011

@organization: cert.org
'''
import logging
import os

from certfuzz.file_handlers.basicfile import BasicFile
from certfuzz.file_handlers.errors import DirectoryError
from certfuzz.fuzztools import filetools

logger = logging.getLogger(__name__)

blacklist = ['.DS_Store', ]

class Directory(object):
    def __init__(self, mydir, child, create=False):
        self.dir = mydir

        if create and not os.path.isdir(self.dir):
            if not os.path.exists(self.dir) and not os.path.islink(self.dir):
                filetools.make_directories(self.dir)
            else:
                raise DirectoryError('Cannot create dir %s - the path already exists, but is not a dir.' % self.dir)

        self._verify_dir()
        self.child = child
        self.files = []
        self.refresh()

    def _verify_dir(self):
        if not os.path.exists(self.dir):
            raise DirectoryError('%s does not exist' % self.dir)
        if not os.path.isdir(self.dir):
            raise DirectoryError('%s is not a dir' % self.dir)

    def refresh(self):
        '''
        Gets all the file paths from self.dir then
        creates corresponding BasicFile objects in self.files
        '''
        self._verify_dir()

        dir_listing = [os.path.join(self.dir, f) for f in os.listdir(self.dir) if not f in blacklist]
        #self.files = [BasicFile(path) for path in dir_listing if os.path.isfile(path)]
        self.files = [BasicFile(path, self.child) for path in dir_listing]
       

    def paths(self):
        '''
        Convenience function to get just the paths to the files
        instead of the file objects
        '''
        return [f.path for f in self.files]

    def __iter__(self):
        self.refresh()
        for f in self.files:
            yield f
