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
Created on Feb 4, 2013

@organization: cert.org
'''
import logging
import os
import re
import string
from subprocess import Popen

from certfuzz import debuggers
from certfuzz.debuggers import msec  # @UnusedImport
from certfuzz.file_handlers.basicfile import BasicFile
from certfuzz.fuzztools.filetools import mkdir_p, all_files, copy_file
from certfuzz.config.simple_loader import load_and_fix_config
from certfuzz.fuzztools.command_line_templating import get_command_args_list

logger = logging.getLogger()
logger.setLevel(logging.WARNING)

def parseiterpath(commandline):
    # Return the path to the iteration's fuzzed file
    for part in commandline.split():
        if 'bff-crash-' in part:
            return part

def getiterpath(msecfile):
    # Find the commandline in an msec file
    with open(msecfile) as mseclines:
        for line in mseclines:
            m = re.match('CommandLine: ', line)
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
                      dest='config',
                      help='path to the configuration file to use')
    parser.add_option('-w', '--windbg', dest='use_windbg',
                      action='store_true',
                      help='Use windbg instead of cdb')
    parser.add_option('-b', '--break', dest='break_on_start',
                      action='store_true',
                      help='Break on start of debugger session')
    parser.add_option('-d', '--debugheap', dest='debugheap',
                      action='store_true',
                      help='Use debug heap')
    parser.add_option('-p', '--debugger', dest='debugger',
                      help='Use specified debugger')
    parser.add_option('-f', '--filepath', dest='filepath',
                      action='store_true', help='Recreate original file path')
    (options, args) = parser.parse_args()

    if options.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    cfg_file = options.config
    logger.debug('WindowsConfig file: %s', cfg_file)

    if len(args) and os.path.exists(args[0]):
        fullpath_fuzzed_file = os.path.abspath(args[0])
        fuzzed_file = BasicFile(fullpath_fuzzed_file)
        logger.info('Fuzzed file is: %s', fuzzed_file.path)
    else:
        parser.error('fuzzedfile must be specified')

    config = load_and_fix_config(cfg_file)

    iterationpath = ''
    if options.filepath:
        # Recreate same file path as fuzz iteration
        resultdir = os.path.dirname(fuzzed_file.path)
        for msecfile in all_files(resultdir, '*.msec'):
            print '** using msecfile: %s' % msecfile
            iterationpath = getiterpath(msecfile)
            break

        if iterationpath:
            iterationdir = os.path.dirname(iterationpath)
            iterationfile = os.path.basename(iterationpath)
            mkdir_p(iterationdir)
            copy_file(fuzzed_file.path,
                      os.path.join(iterationdir, iterationfile))
            fuzzed_file.path = iterationpath

    cmd_as_args = get_command_args_list(
        config['target']['cmdline_template'], fuzzed_file.path)[1]

    args = []

    if options.use_windbg and options.debugger:
        parser.error('Options --windbg and --debugger are mutually exclusive.')

    if options.debugger:
        debugger_app = options.debugger
    elif options.use_windbg:
        debugger_app = 'windbg'
    else:
        debugger_app = 'cdb'

    args.append(debugger_app)

    if not options.debugger:
        # Using cdb or windbg
        args.append('-amsec.dll')
        if options.debugheap or config['debugger']['debugheap']:
            # do not use hd, xd options if debugheap is set
            pass
        else:
            args.extend(('-hd', '-xd', 'gp'))
        if not options.break_on_start:
            args.extend(('-xd', 'bpe', '-G'))
        args.extend(('-xd', 'wob', '-o',))
    args.extend(cmd_as_args)
    logger.info('args %s' % cmd_as_args)

    p = Popen(args, universal_newlines=True)
    p.wait()

if __name__ == '__main__':
    main()
