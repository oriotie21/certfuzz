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
Created on Feb 12, 2014

@author: adh
'''
import logging
import os

from certfuzz.file_handlers.basicfile import BasicFile
from certfuzz.fuzztools.ppid_observer import check_ppid
from certfuzz.iteration.iteration_base import IterationBase
from certfuzz.tc_pipeline.tc_pipeline_linux import LinuxTestCasePipeline
from certfuzz.helpers.misc import fixup_path
from certfuzz.testcase.testcase_linux import LinuxTestcase
from certfuzz.fuzztools.command_line_templating import get_command_args_list

logger = logging.getLogger(__name__)

class LinuxIteration(IterationBase):
    tcpipeline_cls = LinuxTestCasePipeline

    def __init__(self,
                 seedfile=None,
                 seednum=None,
                 workdirbase=None,
                 outdir=None,
                 sf_set=None,
                 uniq_func=None,
                 config=None,
                 fuzzer_cls=None,
                 runner_cls=None,
                 ):

        IterationBase.__init__(self,
                               seedfile=seedfile,
                               seednum=seednum,
                               workdirbase=workdirbase,
                               outdir=outdir,
                               sf_set=sf_set,
                               uniq_func=uniq_func,
                               config=config,
                               fuzzer_cls=fuzzer_cls,
                               runner_cls=runner_cls,
                               )

        self.testcase_base_dir = os.path.join(self.outdir, 'crashers')

        self.pipeline_options.update({'use_valgrind': self.cfg['analyzer']['use_valgrind'],
                                      'use_pin_calltrace': self.cfg['analyzer']['use_pin_calltrace'],
                                      'uniq_log': os.path.join(self.outdir, 'uniquelog.txt'),
                                      'local_dir': fixup_path(self.cfg['directories']['working_dir']),
                                      'minimizertimeout': self.cfg['runoptions']['minimizer_timeout'],
                                      })

    def __enter__(self):
        check_ppid()
        return IterationBase.__enter__(self)

    def _construct_testcase(self):
        with LinuxTestcase(cfg=self.cfg,
                           seedfile=self.seedfile,
                           fuzzedfile=BasicFile(self.fuzzer.output_file_path),
                           program=self.cfg['target']['program'],
                           cmd_template=self.cmd_template,
                           debugger_timeout=self.cfg['debugger']['runtimeout'],
                           cmdlist=get_command_args_list(self.cmd_template,
                                                         infile=self.fuzzer.output_file_path,
                                                         posix=True)[1],
                           backtrace_lines=self.cfg[
                               'debugger']['backtracelevels'],
                           crashers_dir=self.testcase_base_dir,
                           workdir_base=self.working_dir,
                           keep_faddr=self.cfg['runoptions'].get(
                               'keep_unique_faddr', False),
                           save_failed_asserts=self.cfg['analyzer'].get(
                               'savefailedasserts', False),
                           exclude_unmapped_frames=self.cfg['analyzer']['exclude_unmapped_frames']) as testcase:
            # put it on the list for the analysis pipeline
            self.testcases.append(testcase)
