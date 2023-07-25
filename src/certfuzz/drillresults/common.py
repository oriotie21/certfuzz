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
Created on Jun 30, 2014

@organization: cert.org
'''
import StringIO
import argparse
import logging
import zipfile

from certfuzz.fuzztools.filetools import read_bin_file as _read_bin_file

from certfuzz.drillresults.errors import DrillResultsError

logger = logging.getLogger(__name__)

registers = ('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi',
             'edi', 'eip')

registers64 = ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi',
               'rdi', 'rip', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13',
               'r14', 'r15')

reg_set = set(registers)
reg64_set = set(registers64)

def _build_arg_parser():
    usage = "usage: %prog [options]"
    parser = argparse.ArgumentParser(usage)

    group = parser.add_mutually_exclusive_group()
    group.add_argument('--debug', dest='debug', action='store_true',
                       help='Set logging to DEBUG and enable additional debuggers if available')
    group.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                       help='Set logging to INFO level')

    parser.add_argument('-d', '--dir',
                        help='directory to look for results in. Default is "results"',
                        dest='resultsdir',
                        default='../results',
                        type=str)
    parser.add_argument('-j', '--ignore-jit', dest='ignore_jit',
                        action='store_true',
                        help='Ignore PC in unmapped module (JIT)',
                        default=False)
    parser.add_argument('-f', '--force', dest='force',
                        action='store_true',
                        help='Force recalculation of results')
    parser.add_argument('-a', '--all', dest='report_all',
                        help='Report all scores (default is to only print if <=70)',
                        default=False)

    return parser

def root_logger_to_console(args):
    root_logger = logging.getLogger()
    hdlr = logging.StreamHandler()
    root_logger.addHandler(hdlr)

    set_log_level(root_logger, args)

def set_log_level(log_obj, args):
    if args.debug:
        log_obj.setLevel(logging.DEBUG)
        log_obj.debug('Log level = DEBUG')
    elif args.verbose:
        log_obj.setLevel(logging.INFO)
        log_obj.info('Log level = INFO')
    else:
        log_obj.setLevel(logging.WARNING)

def parse_args():
    parser = _build_arg_parser()
    return parser.parse_args()

def carve(string, token1, token2):
    startindex = string.find(token1)
    if startindex == -1:
        # can't find token1
        return ""
    startindex = startindex + len(token1)
    endindex = string.find(token2, startindex)
    if endindex == -1:
        # can't find token2
        return ""
    return string[startindex:endindex]

# Todo: fix this up.  Was added to bring gdb support
def carve2(string):
    delims = [("Exception Faulting Address: ", "\n"),
              ("si_addr:$2 = (void *)", "\n"),
              ("si_addr:$1 = (void *)", "\n")]
    for token1, token2 in delims:
        substring = carve(string, token1, token2)
        if len(substring):
            # returns the first matching substring
            if ' ' in substring:
                addressarray = substring.split(' ')
                # Make sure we get just the address and no symbols
                return addressarray[1]
            else:
                return substring
    # if we got here, no match was found, just return empty string
    return ""

def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        return False

def _read_zip(raw_file_byte_string):
    '''
    If the bytes in raw_file_byte_string look like a zip file,
    attempt to decompress it and return the concatenated contents of the
    decompressed zip
    :param raw_file_byte_string:
    :return string of bytes
    '''
    zbytes = str()

    # For zip files, return the uncompressed bytes
    file_like_content = StringIO.StringIO(raw_file_byte_string)
    if zipfile.is_zipfile(file_like_content):
        # Make sure that it's not an embedded zip
        # (e.g. a DOC file from Office 2007)
        file_like_content.seek(0)
        zipmagic = file_like_content.read(2)
        if zipmagic == 'PK':
            try:
                # The file begins with the PK header
                z = zipfile.ZipFile(file_like_content, 'r')
                for filename in z.namelist():
                    try:
                        zbytes += z.read(filename)
                    except:
                        pass
            except:
                # If the zip container is fuzzed we may get here
                pass
    file_like_content.close()
    return zbytes

def read_bin_file(inputfile):
    '''
    Read binary file
    '''
    filebytes = _read_bin_file(inputfile)

    # append decommpressed zip bytes
    zipbytes = _read_zip(filebytes)

    # _read_zip returns an empty string on failure, so we can safely
    # append its result here
    return filebytes + zipbytes

def main(driller_class=None):
    '''
    Main method for drill results script. Platform-specific customizations are
    passed in via the driller_class argument (which must be implemented elsewhere)
    :param driller_class:
    '''
    args = parse_args()
    root_logger_to_console(args)

    if driller_class is None:
        raise DrillResultsError(
            'A platform-specific driller_class must be specified.')

    with driller_class(ignore_jit=args.ignore_jit,
                       base_dir=args.resultsdir,
                       force_reload=args.force,
                       report_all=args.report_all) as rd:
        rd.drill_results()
