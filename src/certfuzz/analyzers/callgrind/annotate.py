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
Created on Jul 27, 2011

@organization: cert.org
'''

import os
from subprocess import Popen
import logging
from optparse import OptionParser
from certfuzz.analyzers.callgrind.annotation_file import AnnotationFile
from certfuzz.analyzers.callgrind import callgrind
from certfuzz.analyzers.callgrind.errors import CallgrindAnnotateMissingInputFileError, \
    CallgrindAnnotateNoOutputFileError, CallgrindAnnotateEmptyOutputFileError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

OUTFILE_EXT = 'annotated'
get_file = lambda x: '%s.%s' % (x, OUTFILE_EXT)

def main():
    parser = OptionParser()
    parser.add_option('', '--debug', dest='debug', action='store_true', help='Enable debug messages (overrides --verbose)')
    parser.add_option('', '--outfile', dest='outfile', help='file to write output to')
    options, args = parser.parse_args()
    if options.debug:
        logger.setLevel(logging.DEBUG)
    for arg in args:
        opts = {'threshold': 100}
        cga = CallgrindAnnotate(arg, opts)
        a = AnnotationFile(cga.outfile)
        print a.__dict__

def annotate_callgrind(testcase, file_ext='annotated', options=None):
    infile = callgrind.get_file(testcase.fuzzedfile.path)

    if options is None:
        options = {}
    options['threshold'] = '100'

    CallgrindAnnotate(infile, file_ext, options)

def annotate_callgrind_tree(testcase):
    options = {'tree': 'calling'}
    file_ext = 'calltree'

    annotate_callgrind(testcase, file_ext, options)

class CallgrindAnnotate(object):
    '''
    Wrapper class for callgrind_annotate
    '''

    def __init__(self, callgrind_file, file_ext, options=None):
        '''

        @param callgrind_file: A file containing output from valgrind --tool=callgrind
        @param options: Options that will be passed through to callgrind_annotate
        '''
        self.callgrind_file = callgrind_file

        if not os.path.exists(self.callgrind_file):
            raise CallgrindAnnotateMissingInputFileError(self.callgrind_file)

        self.outfile = '%s.%s' % (self.callgrind_file, file_ext)

        if options is None:
            self.options = {}
        else:
            self.options = options

        self.annotate()

    def annotate(self):
        '''
        Run callgrind_annotate, drop results into self.outfile
        @raise CallgrindAnnotateNoOutputFileError: on non-existent output file
        @raise CallgrindAnnotateEmptyOutputFileError: on empty output file
        '''
        args = ['callgrind_annotate']
        for (k, v) in self.options.iteritems():
            args.append('--%s=%s' % (k, v))
        args.append(self.callgrind_file)
        logger.debug('annotate_args: %s', args)
        out_fd = open(self.outfile, 'w')
        p = Popen(args, stdout=out_fd)
        out_fd.close()
        p.wait()

        if not os.path.exists(self.outfile):
            raise CallgrindAnnotateNoOutputFileError(self.outfile)
        elif not os.path.getsize(self.outfile) > 0:
            raise CallgrindAnnotateEmptyOutputFileError(self.outfile)

if __name__ == '__main__':
    hdlr = logging.StreamHandler()
    logger.addHandler(hdlr)

    main()
