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

class CalltreeFile(object):
    '''
    Annotation File object. Reads in a callgrind annotation file and parses it into a dict (self.coverage)
    '''
    def __init__(self, f):
        self.file = f
        self.lines = None

        self._read()
        self.links = {}
        self.counts = {}

        self.nodes_seen = set()
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

    def print_digraph(self):

        node_id = {}

        print 'Digraph G'
        print '{'
        for n_id, node in enumerate(self.nodes_seen):
            short_node = node.split('|')[-1]
            print '\t%d [label="%s"]' % (n_id, short_node)
            node_id[node] = n_id
        for (src, dst) in self.links.iteritems():
            srcnode = node_id[src]
            dstnode = node_id[dst]
            print "\t%s -> %s" % (srcnode, dstnode)
        print '}'

    def process_lines(self):
        caller = None
        called = None
        for l in self.lines:
            logger.debug('Line: %s', l)
            m = re.match('([\d,]+)\s+([*>])\s+(.+)$', l)
            if m:
                (count, typestr, line) = m.groups()
                logger.debug('Count: %s Type: %s Line: %s', count, typestr, line)

                # lib:func (1x) [.so]
                n = re.match('(\S+)(\s+\((\d+)x\))?(\s+\[(.+)\])?', line)
                keyparts = []
                if n:
                    filefunc = n.group(1)
                    # greedy match, separate the string after the last :
                    o = re.match('^(.+):(.+)$', filefunc)
                    if o:
                        (filematch, func) = o.groups()
                    else:
                        logger.debug('Unknown file/function format: %s', filefunc)
                        assert False
                    rpt_count = n.group(3)
                    shared_lib = n.group(5)
#                    logger.debug('Func: %s', func)
                    if rpt_count:
#                        logger.debug('Rpt: %d', int(rpt_count))
                        pass
                    if shared_lib:
#                        logger.debug('ShLib: %s', shared_lib)
                        keyparts.append(shared_lib)
                    keyparts.append(filematch)
                    keyparts.append(func)
                else:
                    logger.debug('Unknown line format: %s', line)
                    continue

                key = '|'.join(keyparts)
                self.nodes_seen.add(key)
                if typestr == "*":
                    caller = key
                    called = None
                elif typestr == ">":
                    called = key

#                print line
                if caller and called:
                    combined_key = ' -> '.join((caller, called))

                    logger.debug('Link: %s -> %s', caller, called)
                    self.links[caller] = called

                    logger.debug('Count: %s %s', combined_key, count)
                    self.counts[combined_key] = count

            else:
                logger.debug('Unmatched: %s', l)
                continue

if __name__ == '__main__':
    from optparse import OptionParser

    hdlr = logging.StreamHandler()
    logger.addHandler(hdlr)

    parser = OptionParser()
    parser.add_option('', '--debug', dest='debug', action='store_true', help='Enable debug messages (overrides --verbose)')
    parser.add_option('', '--outfile', dest='outfile', help='file to write output to')
    (options, args) = parser.parse_args()

    if options.debug:
        logger.setLevel(logging.DEBUG)

    for arg in args:
        a = CalltreeFile(arg)

        a.print_digraph()
