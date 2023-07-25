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
Created on Mar 2, 2012

@author: adh
'''
import glob
import logging
import os

from certfuzz.testcase.testcase_windows import WindowsTestcase
from certfuzz.file_handlers.basicfile import BasicFile
from certfuzz.file_handlers.tmp_reaper import TmpReaper
from certfuzz.fuzztools.filetools import delete_files_or_dirs
from certfuzz.iteration.iteration_base import IterationBase
from certfuzz.tc_pipeline.tc_pipeline_windows import WindowsTestCasePipeline
from certfuzz.fuzztools.command_line_templating import get_command_args_list

# from certfuzz.iteration.iteration_base import IterationBase2
logger = logging.getLogger(__name__)

class WindowsIteration(IterationBase):
    tcpipeline_cls = WindowsTestCasePipeline

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
                 debug=False,
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

        self.debug = debug

        self.keep_uniq_faddr = config['runoptions'].get(
            'keep_unique_faddr', False)

        if self.runner_cls.is_nullrunner:
            # null runner_cls case
            self.retries = 0
        else:
            # runner_cls is not null
            self.retries = 4
        self.pipeline_options.update({'keep_duplicates': self.cfg['runoptions'].get('keep_duplicates', False),
                                      'keep_heisenbugs': self.cfg['campaign'].get('keep_heisenbugs', False),
                                      'cmd_template': self.cfg['target']['cmdline_template'],
                                      'null_runner': self.runner_cls.is_nullrunner,
                                      })
    def __exit__(self, etype, value, traceback):
        try:
            handled = IterationBase.__exit__(self, etype, value, traceback)
        except WindowsError as e:
            logger.warning('Caught WindowsError in iteration exit: %s', e)
            handled = True

        if etype and not handled:
            logger.warning(
                'WindowsIteration terminating abnormally due to %s: %s',
                etype.__name__,
                value
            )
            if self.debug:
                # don't clean up if we're in debug mode and have an unhandled
                # exception
                logger.debug('Skipping cleanup since we are in debug mode.')
                return handled

        self._tidy()
        return handled

    def _tidy(self):
        # wrap up this iteration
        paths = []
        # sweep up any iteration temp dirs left behind previously
        pattern = os.path.join(self.workdirbase, self._tmpdir_pfx + '*')
        paths.extend(glob.glob(pattern))
        delete_files_or_dirs(paths)
        # wipe them out, all of them
        TmpReaper().clean_tmp()
    def _construct_testcase(self):
        with WindowsTestcase(cfg=self.cfg, seedfile=self.seedfile,
                             fuzzedfile=BasicFile(
                                 self.fuzzer.output_file_path, self.cfg['target']['mutate']),
                             program=self.cfg['target']['program'],
                             cmd_template=self.cmd_template,
                             debugger_timeout=self.cfg[
                                 'debugger']['runtimeout'],
                             cmdlist=get_command_args_list(
                                 self.cmd_template, self.fuzzer.output_file_path, name=self.cfg['target']['name'])[1],
                             dbg_opts=self.cfg['debugger'],
                             workdir_base=self.working_dir,
                             keep_faddr=self.cfg['runoptions'].get(
                                 'keep_unique_faddr', False),
                             heisenbug_retries=self.retries,
                             copy_fuzzedfile=self.fuzzer.fuzzed_changes_input) as testcase:

            # put it on the list for the analysis pipeline
            
            self.testcases.append(testcase)
