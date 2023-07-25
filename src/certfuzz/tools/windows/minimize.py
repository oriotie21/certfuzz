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
Created on Apr 9, 2012

@organization: cert.org
'''

import logging
import os
import sys
import string
import platform

try:
    from certfuzz import debuggers
    from certfuzz.fuzztools import filetools, text
    from certfuzz.file_handlers.basicfile import BasicFile
    from certfuzz.minimizer.win_minimizer import WindowsMinimizer as Minimizer
    from certfuzz.testcase.testcase_windows import WindowsTestcase
    from certfuzz.debuggers import msec  # @UnusedImport
    from certfuzz.fuzztools.command_line_templating import get_command_args_list
    from certfuzz.config.simple_loader import load_and_fix_config
except ImportError:
    # if we got here, we probably don't have .. in our PYTHONPATH
    import sys
    mydir = os.path.dirname(os.path.abspath(__file__))
    parentdir = os.path.abspath(os.path.join(mydir, '..'))
    sys.path.append(parentdir)
    from certfuzz import debuggers
    from certfuzz.fuzztools import filetools, text
    from certfuzz.file_handlers.basicfile import BasicFile
    from certfuzz.minimizer.win_minimizer import WindowsMinimizer as Minimizer
    from certfuzz.testcase.testcase_windows import WindowsTestcase
    from certfuzz.debuggers import msec  # @UnusedImport
    from certfuzz.fuzztools.command_line_templating import get_command_args_list
    from certfuzz.config.simple_loader import load_and_fix_config

logger = logging.getLogger()
logger.setLevel(logging.WARNING)

def _create_minimizer_cfg(cfg):
    class DummyCfg(object):
        pass
    config = DummyCfg()
    config.backtracelevels = 5  # doesn't matter what this is, we don't use it
    config.debugger_timeout = cfg['runner']['runtimeout'] * 2
    if config.debugger_timeout < 10:
        config.debugger_timeout = 10
    template = string.Template(cfg['target']['cmdline_template'])
    config.get_command_args_list = lambda x: get_command_args_list(
        template, x)[1]
    config.program = cfg['target']['program']
    config.exclude_unmapped_frames = False
    config.watchdogfile = os.devnull
    return config

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
    parser.add_option('-t', '--target', dest='target',
                      help='the file to minimize to (typically the seedfile)')
    parser.add_option('-o', '--outdir', dest='outdir',
                      help='dir to write output to')
    parser.add_option('-s', '--stringmode', dest='stringmode',
                      action='store_true',
                      help='minimize to a string rather than to a target file')
    parser.add_option('-x', '--preferx', dest='prefer_x_target',
                      action='store_true',
                      help='Minimize to \'x\' characters instead of Metasploit string pattern')
    parser.add_option('-f', '--faddr', dest='keep_uniq_faddr',
                      action='store_true',
                      help='Use exception faulting addresses as part of testcase signature')
    parser.add_option('-b', '--bitwise', dest='bitwise', action='store_true',
                      help='if set, use bitwise hamming distance. Default is bytewise')
    parser.add_option('-c', '--confidence', dest='confidence',
                      help='The desired confidence level (default: 0.999)')
    parser.add_option('-g', '--target-size-guess', dest='initial_target_size',
                      help='A guess at the minimal value (int)')
    parser.add_option('', '--config', default='configs/bff.yaml',
                      dest='config', help='path to the configuration file to use')
    parser.add_option('', '--timeout', dest='timeout',
                      metavar='N', type='int', default=0,
                      help='Stop minimizing after N seconds (default is 0, never time out).')
    parser.add_option('-k', '--keepothers', dest='keep_other_crashes',
                      action='store_true',
                      help='Keep other testcase hashes encountered during minimization')
    (options, args) = parser.parse_args()

    if options.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    if options.config:
        cfg_file = options.config
    else:
        cfg_file = "../configs/bff.yaml"
    logger.debug('WindowsConfig file: %s', cfg_file)

    if options.stringmode and options.target:
        parser.error(
            'Options --stringmode and --target are mutually exclusive.')

    # Set some default options. Fast and loose if in string mode
    # More precise with minimize to seedfile
    if not options.confidence:
        if options.stringmode:
            options.confidence = 0.5
        else:
            options.confidence = 0.999
    if not options.initial_target_size:
        if options.stringmode:
            options.initial_target_size = 100
        else:
            options.initial_target_size = 1

    if options.confidence:
        try:
            options.confidence = float(options.confidence)
        except:
            parser.error('Confidence must be a float.')
    if not 0.0 < options.confidence < 1.0:
        parser.error('Confidence must be in the range 0.0 < c < 1.0')

    confidence = options.confidence

    if options.outdir:
        outdir = options.outdir
    else:
        outdir = 'minimizer_out'
    outdir = os.path.abspath(outdir)

    filetools.make_directories(outdir)

    if len(args) and os.path.exists(args[0]):
        fuzzed_file = BasicFile(args[0])
        logger.info('Fuzzed file is: %s', fuzzed_file.path)
    else:
        parser.error('fuzzedfile must be specified')

    cfg = load_and_fix_config(cfg_file)

    if options.target:
        seedfile = BasicFile(options.target)
    else:
        seedfile = None

    min2seed = not options.stringmode
    filename_modifier = ''
    retries = 0
    debugger_class = msec.MsecDebugger

    cmd_as_args = get_command_args_list(
        cfg['target']['cmdline_template'], fuzzed_file.path)[1]

    # Figure out an appropriate timeout to use based on the config
    winver = sys.getwindowsversion().major
    machine = platform.machine()
    hook_incompatible = winver > 5 or machine == 'AMD64'
    debugger_timeout = cfg['runner']['runtimeout']
    if not hook_incompatible:
        # Assume the user has tuned timeout to the hook.
        # Allow extra time for the debugger to run
        debugger_timeout *= 2
        if debugger_timeout < 10:
            debugger_timeout = 10
    cfg['debugger']['runtimeout'] = debugger_timeout

    with WindowsTestcase(cfg=cfg,
                         seedfile=seedfile,
                         fuzzedfile=fuzzed_file,
                         program=cfg['target']['program'],
                         cmd_template=cfg['target']['cmdline_template'],
                         debugger_timeout=cfg['debugger']['runtimeout'],
                         cmdlist=cmd_as_args,
                         dbg_opts=cfg['debugger'],
                         workdir_base=outdir,
                         keep_faddr=options.keep_uniq_faddr,
                         heisenbug_retries=retries
                         ) as testcase:
        filetools.make_directories(testcase.tempdir)
        logger.info('Copying %s to %s', fuzzed_file.path, testcase.tempdir)
        filetools.copy_file(fuzzed_file.path, testcase.tempdir)

        minlog = os.path.join(outdir, 'min_log.txt')

        with Minimizer(cfg=cfg, testcase=testcase, crash_dst_dir=outdir,
                       seedfile_as_target=min2seed, bitwise=options.bitwise,
                       confidence=confidence, tempdir=outdir,
                       logfile=minlog, maxtime=options.timeout,
                       preferx=options.prefer_x_target) as minimize:
            minimize.save_others = options.keep_other_crashes
            minimize.target_size_guess = int(options.initial_target_size)
            minimize.go()

        if options.stringmode:
            logger.debug('x character substitution')
            length = len(minimize.fuzzed_content)
            if options.prefer_x_target:
                # We minimized to 'x', so we attempt to get metasploit as a
                # freebie
                targetstring = list(text.metasploit_pattern_orig(length))
                filename_modifier = '-mtsp'
            else:
                # We minimized to metasploit, so we attempt to get 'x' as a
                # freebie
                targetstring = list('x' * length)
                filename_modifier = '-x'

            fuzzed = list(minimize.fuzzed_content)
            for idx in minimize.bytemap:
                logger.debug('Swapping index %d', idx)
                targetstring[idx] = fuzzed[idx]
            filename = ''.join(
                (testcase.fuzzedfile.root, filename_modifier, testcase.fuzzedfile.ext))
            metasploit_file = os.path.join(testcase.tempdir, filename)

            f = open(metasploit_file, 'wb')
            try:
                f.writelines(targetstring)
            finally:
                f.close()
        testcase.copy_files(outdir)
        testcase.clean_tmpdir()

if __name__ == '__main__':
    main()
