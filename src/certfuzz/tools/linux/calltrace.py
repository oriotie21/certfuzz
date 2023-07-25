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
Created on April 28, 2013

@organization: cert.org
'''
import logging
import os
import re
import platform
from subprocess import Popen
from certfuzz.config.simple_loader import load_and_fix_config
from certfuzz.fuzztools.command_line_templating import get_command_args_list

try:
    from certfuzz.fuzztools.filetools import mkdir_p, all_files, copy_file
    from certfuzz.file_handlers.basicfile import BasicFile
except ImportError:
    # if we got here, we probably don't have .. in our PYTHONPATH
    import sys
    mydir = os.path.dirname(os.path.abspath(__file__))
    parentdir = os.path.abspath(os.path.join(mydir, '..'))
    sys.path.append(parentdir)
    from certfuzz.fuzztools.filetools import mkdir_p, all_files, copy_file
    from certfuzz.file_handlers.basicfile import BasicFile

logger = logging.getLogger()
logger.setLevel(logging.WARNING)

def parseiterpath(commandline):
    # Return the path to the iteration's fuzzed file
    for part in commandline.split():
        if 'campaign_' in part and 'iteration_' in part:
            # This is the part of the commandline that looks like it's
            # the fuzzed file
            return part

def getiterpath(gdbfile):
    # Find the commandline in an msec file
    with open(gdbfile) as gdblines:
        for line in gdblines:
            m = re.match('Running: ', line)
            if m:
                return parseiterpath(line)

def main():
    from optparse import OptionParser

    hdlr = logging.StreamHandler()
    logger.addHandler(hdlr)

    usage = "usage: %prog [options] fuzzedfile"
    parser = OptionParser(usage)
    parser.add_option('', '--debug', dest='debug', action='store_true',
                      help='Enable debug messages (overrides --verbose)')
    parser.add_option('', '--verbose', dest='verbose', action='store_true',
                      help='Enable verbose messages')
    parser.add_option('-c', '--config', default='configs/bff.yaml',
                      dest='config', help='path to the configuration file to use')
    parser.add_option('-a', '--args', dest='print_args',
                      action='store_true',
                      help='Print function arguments')
    parser.add_option('-o', '--out', dest='outfile',
                      help='PIN output file')
    parser.add_option('-f', '--filepath', dest='filepath',
                      action='store_true', help='Recreate original file path')

    (options, args) = parser.parse_args()

    if options.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    if options.outfile:
        outfile = options.outfile
    else:
        outfile = 'calltrace.log'

    cfg_file = options.config
    logger.debug('Config file: %s', cfg_file)

    if len(args) and os.path.exists(args[0]):
        fullpath_fuzzed_file = os.path.abspath(args[0])
        fuzzed_file = BasicFile(fullpath_fuzzed_file)
        logger.info('Fuzzed file is: %s', fuzzed_file.path)
    else:
        parser.error('fuzzedfile must be specified')

    iterationpath = ''

    if options.filepath:
        # Recreate same file path as fuzz iteration
        resultdir = os.path.dirname(fuzzed_file.path)
        for gdbfile in all_files(resultdir, '*.gdb'):
            print '** using gdb: %s' % gdbfile
            iterationpath = getiterpath(gdbfile)
            break
        if iterationpath:
            iterationdir = os.path.dirname(iterationpath)
            iterationfile = os.path.basename(iterationpath)
            if iterationdir:
                mkdir_p(iterationdir)
                copy_file(fuzzed_file.path,
                          os.path.join(iterationdir, iterationfile))
                fullpath_fuzzed_file = iterationpath

    config = load_and_fix_config(cfg_file)

    cmd_as_args = get_command_args_list(
        config['target']['cmdline_template'], fullpath_fuzzed_file)[1]
    args = []

    pin = os.path.expanduser('~/pin/pin')
    pintool = os.path.expanduser('~/pintool/calltrace.so')
    args = [pin, '-injection', 'child', '-t',
            pintool, '-o', outfile]
    if options.print_args:
        args.append('-a')
    args.append('--')
    args.extend(cmd_as_args)

    logger.info('args %s' % args)

    p = Popen(args, universal_newlines=True)
    p.wait()

if __name__ == '__main__':
    main()
