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
Created on Mar 16, 2011

@organization: cert.org
'''
import json
import os

from certfuzz.file_handlers.basicfile import BasicFile
from certfuzz.file_handlers.errors import SeedFileError
from certfuzz.fuzztools import filetools
from certfuzz.fuzztools.rangefinder import RangeFinder

# TODO: replace with a common function in some helper module
def print_dict(d, indent=0):
    for (k, v) in d.iteritems():
        indent_str = '  ' * indent
        if isinstance(v, dict):
            print indent_str + k
            print_dict(v, indent + 1)
        else:
            print indent_str + "%s (%s): %s" % (k, type(v).__name__, v)

class SeedFile(BasicFile):
    '''
    '''

    def __init__(self, output_base_dir, path, child):
        '''
        Creates an output dir for this seedfile based on its md5 hash.
        @param output_base_dir: The base directory for output files
        @raise SeedFileError: zero-length files will raise a SeedFileError
        '''
        BasicFile.__init__(self, path, child)

        '''
        if not self.len > 0:
            raise SeedFileError(
                'You cannot do bitwise fuzzing on a zero-length file: %s' % self.path)
        '''
        
        # use len for bytewise, bitlen for bitwise
        if self.len > 1:
            self.range_min = 1.0 / self.len
            self.range_max = 1.0 - self.range_min
        else:
            self.range_min = 0
            self.range_max = 1

        self.tries = 0

        self.rangefinder = RangeFinder(self.range_min, self.range_max)

    def cache_key(self):
        return 'seedfile-%s' % self.md5

    def pkl_file(self):
        return '%s.pkl' % self.md5

    def to_json(self, sort_keys=True, indent=None):
        state = self.__dict__.copy()
        state['rangefinder'] = state['rangefinder'].to_json(
            sort_keys=sort_keys, indent=indent)
        return json.dumps(state, sort_keys=sort_keys, indent=indent)
