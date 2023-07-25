#-*- coding:utf-8 -*-
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
Created on Oct 11, 2012

@organization: cert.org
'''
import logging
import os
import tempfile

from certfuzz.file_handlers.basicfile import BasicFile
from certfuzz.fuzztools import filetools, hamming
from certfuzz.fuzztools.filetools import check_zip_file, mkdir_p
from certfuzz.fuzztools.command_line_templating import get_command_args_list
from pprint import pformat
from distutils.dir_util import copy_tree

logger = logging.getLogger(__name__)

class TestCaseBase(object):
    '''
    A BFF test case represents everything we know about a fuzzer finding.
    '''
    _tmp_sfx = ''
    _tmp_pfx = 'BFF_testcase_'
    _debugger_cls = None

    def __init__(self,
                 cfg,
                 seedfile,
                 fuzzedfile,
                 program,
                 cmd_template,
                 workdir_base,
                 cmdlist,
                 keep_faddr=False,
                 dbg_timeout=30):

        logger.debug('Inititalize TestCaseBase')
        self.cfg = cfg
        self.cmd_template = cmd_template
        self.cmdlist = cmdlist
        self.copy_fuzzedfile = True
        self.dbg_file = None
        self.dbg_files = {}
        self.debugger_missed_stack_corruption = False
        self.debugger_template = None
        self.debugger_timeout = dbg_timeout
        # Exploitability is UNKNOWN unless proven otherwise
        self.exp = 'UNDETERMINED'
        self.hd_bits = None
        self.hd_bytes = None
        self.faddr = None
        self.fuzzedfile = fuzzedfile
        self.is_corrupt_stack = False
        # Not a crash until we're sure
        self.is_crash = False
        # All crashes are heisenbugs until proven otherwise
        self.is_heisenbug = True
        self.is_unique = False
        self.is_zipfile = False
        self.keep_uniq_faddr = keep_faddr
        self.pc = None
        self.pc_in_function = False
        self.program = program
        self.target_dir = None
        self.seedfile = seedfile
        self.should_proceed_with_analysis = False
        self.signature = None
        self.total_stack_corruption = False
        self.workdir_base = workdir_base
        self.working_dir = None

    def __enter__(self):
        mkdir_p(self.workdir_base)
        self.update_crash_details()
        return self

    def __exit__(self, etype, value, traceback):
        pass

    def __repr__(self):
        return pformat(self.__dict__)

    def _get_output_dir(self, *args):
        raise NotImplementedError

    def _rename_dbg_files(self):
        raise NotImplementedError

    def _rename_fuzzed_file(self):
        raise NotImplementedError

    def _set_attr_from_dbg(self, attrname):
        raise NotImplementedError

    def _verify_crash_base_dir(self):
        raise NotImplementedError

    def clean_tmpdir(self):
        logger.debug('Cleaning up %s', self.tempdir)
        if os.path.exists(self.tempdir):
            filetools.delete_files_or_dirs([self.tempdir])
        else:
            logger.debug('No tempdir at %s', self.tempdir)

        if os.path.exists(self.tempdir):
            logger.debug('Unable to remove tempdir %s', self.tempdir)

    def confirm_crash(self):
        raise NotImplementedError

    def copy_files_to_temp(self):
        if self.fuzzedfile and self.copy_fuzzedfile:
            
            if(os.path.isdir(self.fuzzedfile.path)):
            #print("path : "+self.fuzzedfile.root)
                new_tmpdir = os.path.join(self.tempdir, self.fuzzedfile.root)
                os.mkdir(new_tmpdir)
                copy_tree(self.fuzzedfile.path , new_tmpdir)
            
            else:
                filetools.copy_file(self.fuzzedfile.path, self.tempdir)
        else:
            # We're in verify mode. Set the fuzzedfile to be the seedfile,
            # since we didn't mutate anything
            self.fuzzedfile = self.seedfile

        '''
        아랫줄 때문에 중복 복사 발생
        '''
        #if self.seedfile:
        #    filetools.copy_file(self.seedfile.path, self.tempdir)

        # TODO: This seems hacky. Should be better way to have
        # minimizer_log.txt and core files survive update_crash_details
        minlog = os.path.join(self.fuzzedfile.dirname, 'minimizer_log.txt')
        if os.path.exists(minlog):
            filetools.copy_file(minlog, self.tempdir)

        corefile = os.path.join(self.workdir_base, 'core')
        if os.path.exists(corefile):
            filetools.copy_file(corefile, self.tempdir)

        calltracefile = os.path.join(
            self.fuzzedfile.dirname, '%s.calltrace' % self.fuzzedfile.basename)
        if os.path.exists(calltracefile):
            filetools.copy_file(calltracefile, self.tempdir)

        new_fuzzedfile = os.path.join(self.tempdir, self.fuzzedfile.basename)
        self.fuzzedfile = BasicFile(new_fuzzedfile, self.cfg['target']['mutate'])

    def copy_files(self, outdir):
        crash_files = os.listdir(self.tempdir)
        for f in crash_files:
            filepath = os.path.join(self.tempdir, f)
            if os.path.isfile(filepath):
                filetools.copy_file(filepath, outdir)

    def debug(self, tries_remaining=None):
        raise NotImplementedError

    def debug_once(self):
        raise NotImplementedError

    def delete_files(self):
        if os.path.isdir(self.fuzzedfile.dirname):
            logger.debug('Deleting files from %s', self.fuzzedfile.dirname)
            filetools.delete_files_or_dirs([self.fuzzedfile.dirname])

    def get_debug_output(self, f):
        raise NotImplementedError

    def get_signature(self):
        raise NotImplementedError

    def set_debugger_template(self, *args):
        pass

    def update_crash_details(self):
        # We might be updating crash details because we have a new fuzzedfile
        # (with a different path)
        self.cmdlist = get_command_args_list(
            self.cmd_template, infile=self.fuzzedfile.path)[1]
        self.cmdargs = self.cmdlist[1:]
        self.tempdir = tempfile.mkdtemp(
            prefix=self._tmp_pfx, suffix=self._tmp_sfx, dir=self.workdir_base)
        self.copy_files_to_temp()

#        raise NotImplementedError
    def calculate_hamming_distances(self):
        # If the fuzzed file is a valid zip, then we're fuzzing zip contents,
        # not the container
        self.is_zipfile = check_zip_file(self.fuzzedfile.path)
        try:
            if self.is_zipfile:
                self.hd_bits = hamming.bitwise_zip_hamming_distance(
                    self.seedfile.path, self.fuzzedfile.path)
                self.hd_bytes = hamming.bytewise_zip_hamming_distance(
                    self.seedfile.path, self.fuzzedfile.path)
            else:
                self.hd_bits = hamming.bitwise_hamming_distance(
                    self.seedfile.path, self.fuzzedfile.path, child=self.cfg['target']['mutate'])
                self.hd_bytes = hamming.bytewise_hamming_distance(
                    self.seedfile.path, self.fuzzedfile.path, child=self.cfg['target']['mutate'])
        except KeyError:
            # one of the files wasn't defined
            logger.warning(
                'Cannot find either sf_path or minimized file to calculate Hamming Distances')
        except AssertionError:
            # Some apps change the size of the file they open.  BFF-1017
            logger.warning(
                'File size changed on disk. Cannot calculate Hamming Distances')
            # We'll use -1 HD as indication of unexpected size change
            self.hd_bits = -1
            self.hd_bytes = -1

        logger.info("crasher=%s bitwise_hd=%d", self.signature, self.hd_bits)
        logger.info("crasher=%s bytewise_hd=%d", self.signature, self.hd_bytes)

    def calculate_hamming_distances_a(self):
        with open(self.fuzzedfile.path, 'rb') as fd:
            fuzzed = fd.read()

        a_string = 'x' * len(fuzzed)

        self.hd_bits = hamming.bitwise_hd(a_string, fuzzed)
        logger.info("crasher=%s bitwise_hd=%d", self.signature, self.hd_bits)

        self.hd_bytes = hamming.bytewise_hd(a_string, fuzzed)
        logger.info(
            "crasher=%s bytewise_hd=%d", self.signature, self.hd_bytes)
