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
Created on Aug 16, 2011

@organization: cert.org
'''
import logging
from optparse import OptionParser

from certfuzz.fuzztools.similarity_matrix import SimilarityMatrix
from certfuzz.fuzztools.similarity_matrix import SimilarityMatrixError
from certfuzz.fuzztools.distance_matrix import DistanceMatrixError

logger = logging.getLogger()
logger.setLevel(logging.WARNING)

def main():
    parser = OptionParser(usage='%prog [options] <dir1> ... <dirN>')
    parser.add_option('', '--debug', dest='debug', action='store_true', help='Enable debug messages (overrides --verbose)')
    parser.add_option('', '--verbose', dest='verbose', action='store_true', help='Enable verbose messages')
    parser.add_option('', '--outfile', dest='outfile', help='file to write output to')
    parser.add_option('', '--precision', dest='precision', help='Number of digits to print in similarity')
    parser.add_option('', '--style', dest='style', help='Either "list" or "tree"')

    (options, args) = parser.parse_args()

    hdlr = logging.StreamHandler()
    logger.addHandler(hdlr)

    if options.verbose:
        logger.setLevel(logging.INFO)
    if options.debug:
        logger.setLevel(logging.DEBUG)

    if not len(args):
        print "You must specify at least one dir to crawl.\n"
        parser.print_help()
        exit(-1)
    else:
        logger.debug('Args: %s', args)

    try:
        sim = SimilarityMatrix(args)
    except SimilarityMatrixError, e:
        print 'Error:', e
        exit(-1)

    if options.precision:
        sim.precision = options.precision

    if not options.style or options.style == 'list':
        # Print the results
        if options.outfile:
            target = options.outfile
        else:
            # default goes to sys.stdout
            target = None

        sim.print_to(target)

    elif options.style == 'tree':
        from certfuzz.fuzztools.distance_matrix import DistanceMatrix

        if options.outfile:
            target = options.outfile
        else:
            target = 'cluster.png'

        dm = DistanceMatrix(sim.sim)
        try:
            dm.to_image(target)
        except DistanceMatrixError, e:
            print "PIL not installed, skipping image creation."
    else:
        # it's something other than None, list, or tree
        print "The only allowed values for --style are 'list' and 'tree': %s" % options.style
        parser.print_help()
        exit(-1)

if __name__ == '__main__':
    main()
