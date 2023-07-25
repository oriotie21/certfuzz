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
Created on Jun 14, 2013

'''

import os
import re
import sys
import shutil
from optparse import OptionParser

regex = {
        'crasher': re.compile('^sf_.+-\w+.\w+$'),
        }

def copycrashers(tld, outputdir):
    # Walk the results directory
    for root, dirs, files in os.walk(tld):
        crash_hash = os.path.basename(root)
        # Only use directories that are hashes
        if "0x" in crash_hash:
            # Check each of the files in the hash directory
            for current_file in files:
                # This gives us the crasher file name
                if regex['crasher'].match(current_file) and 'minimized' not in current_file:
                    crasher_file = os.path.join(root, current_file)
                    print 'Copying %s to %s ...' % (crasher_file, outputdir)
                    shutil.copy(crasher_file, outputdir)

def main():
    # If user doesn't specify a directory to crawl, use "results"
    usage = "usage: %prog [options]"
    parser = OptionParser(usage=usage)
    parser.add_option('-d', '--dir',
                      help='directory to look for results in. Default is "results"',
                      dest='resultsdir', default='results')
    parser.add_option('-o', '--outputdir', dest='outputdir', default='seedfiles',
                      help='Directory to put crashing testcases')
    (options, args) = parser.parse_args()
    outputdir = options.outputdir
    tld = options.resultsdir
    if not os.path.isdir(tld):
        if os.path.isdir('../results'):
            tld = '../results'
        elif os.path.isdir('crashers'):
            # Probably using FOE 1.0, which defaults to "crashers" for output
            tld = 'crashers'
        else:
            print 'Cannot find resuls directory %s' % tld
            sys.exit(0)

    if not os.path.isdir(outputdir):
        if os.path.isdir('../seedfiles'):
            outputdir = '../seedfiles'
        else:
            print 'cannot find output directory %s' % outputdir
            sys.exit(0)

    copycrashers(tld, outputdir)

if __name__ == '__main__':
    main()
