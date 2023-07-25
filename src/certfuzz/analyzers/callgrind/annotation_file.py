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
Created on Aug 15, 2011

@organization: cert.org
'''
import re
import logging
from certfuzz.analyzers.callgrind.errors import CallgrindAnnotateNoOutputFileError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class AnnotationFile(object):
    '''
    Annotation File object. Reads in a callgrind annotation file and parses it into a dict (self.coverage)
    '''
    def __init__(self, f):
        self.file = f
        self.lines = None

        self._read()
        self.coverage = {}
        self.process_lines()

    def _read(self):
        try:
            fd = open(self.file, 'r')
            self.lines = [l.strip() for l in fd.readlines()]
        except:
            raise CallgrindAnnotateNoOutputFileError(self.file)

    def print_lines(self):
        for l in self.lines:
            print l

    def print_coverage(self):
        for (k, v) in self.coverage.iteritems():
            print k, v

    def process_coverage_line(self, line):
        m = re.match('([\d,]+)\s+([^:]+):(.+)\s+\[([^]]*)\]', line)
        if m:
            count = int(m.group(1).replace(',', ''))
            filematch = m.group(2)
            func = m.group(3)
            lib = ''
            if m.group(4):
                lib = m.group(4)
            logger.debug("COUNT=%d FILE=%s FUNC=%s LIB=%s", count, filematch, func, lib)
            key = ':'.join((lib, filematch, func))
            self.coverage[key] = count
        else:
            logger.debug("Unprocessed: %s" % line)

    def process_lines(self):
        for line in self.lines:
            self.process_coverage_line(line)

if __name__ == '__main__':
    from optparse import OptionParser

    hdlr = logging.StreamHandler()
    logger.addHandler(hdlr)

    parser = OptionParser()
    parser.add_option('', '--debug', dest='debug', action='store_true', help='Enable debug messages (overrides --verbose)')
    parser.add_option('', '--outfile', dest='outfile', help='file to write output to')
    (options, args) = parser.parse_args()

    for arg in args:
        a = AnnotationFile(arg)
        print a.__dict__
