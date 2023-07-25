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
Created on Jan 10, 2014

@author: adh
'''
import logging
import os
import platform
import sys
import time
from threading import Timer

from certfuzz.campaign.campaign_base import CampaignBase
from certfuzz.file_handlers.seedfile_set import SeedfileSet
from certfuzz.fuzzers.errors import FuzzerExhaustedError
from certfuzz.iteration.iteration_windows import WindowsIteration
from certfuzz.runners.killableprocess import Popen
from certfuzz.fuzztools.command_line_templating import get_command_args_list
from certfuzz.file_handlers.watchdog_file import TWDF

logger = logging.getLogger(__name__)

class WindowsCampaign(CampaignBase):
    '''
    Extends CampaignBase to add windows-specific features like ButtonClicker
    '''

    def __init__(self, config_file, result_dir=None, debug=False):
        CampaignBase.__init__(self, config_file, result_dir, debug)
        self.use_buttonclicker = self.config[
            'campaign'].get('use_buttonclicker', False)
        self.runner_module_name = 'certfuzz.runners.winrun'
        self.debugger_module_name = 'certfuzz.debuggers.gdb'
        TWDF.disable()

    def _pre_enter(self):
        # check to see if the platform supports winrun
        # set runner module to none otherwise

        if sys.platform != 'win32':
            return

        if not self.runner_module_name == 'certfuzz.runners.winrun':
            return

        # if we got here, we're on win32, and trying to use winrun
        winver = sys.getwindowsversion().major
        machine = platform.machine()
        hook_incompatible = winver > 5 or machine == 'AMD64'

        if not hook_incompatible:
            # Since we've simplified configuration to include only one run timeout, we
            # need to account for the fact that a debugger-run instance could take
            # longer than a hooked instance.
            debugger_timeout = self.config['runner']['runtimeout'] * 2
            if debugger_timeout < 10:
                debugger_timeout = 10
            self.config['debugger']['runtimeout'] = debugger_timeout
            return

        logger.debug(
            'winrun is not compatible with Windows %s %s. Overriding.', winver, machine)
        self.runner_module_name = 'certfuzz.runners.nullrun'

        # Assume that since we're not using the hook, the user has configured the timeout
        # to be reasonble for debugger-invoked instances.
        self.config['debugger']['runtimeout'] = self.config[
            'runner']['runtimeout']

    def _post_enter(self):
        self._start_buttonclicker()
        self._cache_app()

    def _pre_exit(self):
        self._stop_buttonclicker()

    def _cache_app(self):
        logger.debug(
            'Caching application %s and determining if we need to watch the CPU...', self.program)
        sf = self.seedfile_set.next_item()
        cmdargs = get_command_args_list(
            self.config['target']['cmdline_template'], infile=sf.path, name=self.config['target']['name'])[1]
        logger.info('Invoking %s' % cmdargs)

        # Use overriden Popen that uses a job object to make sure that
        # child processes are killed
        p = Popen(cmdargs)
        runtimeout = self.config['runner']['runtimeout']
        logger.debug('...Timer: %f', runtimeout)
        t = Timer(runtimeout, self.kill, args=[p])
        logger.debug('...timer start')
        t.start()
        p.wait()
        logger.debug('...timer stop')
        t.cancel()
        if not self.gui_app:
            logger.debug('This seems to be a CLI application.')
        try:
            runner_watchcpu = str(self.config['runner']['watchcpu']).lower()
            debugger_watchcpu = runner_watchcpu
        except KeyError:
            self.config['runner']['watchcpu'] = 'auto'
            self.config['debugger']['watchcpu'] = 'auto'
            runner_watchcpu = 'auto'
            debugger_watchcpu = 'auto'
        if runner_watchcpu == 'auto':
            logger.debug('Disabling runner CPU monitoring for dynamic timeout')
            self.config['runner']['watchcpu'] = False
        if debugger_watchcpu == 'auto':
            logger.debug(
                'Disabling debugger CPU monitoring for dynamic timeout')
            self.config['debugger']['watchcpu'] = False

        logger.info(
            'Please ensure that the target program has just executed successfully')
        time.sleep(10)

    def kill(self, p):
        # The app didn't complete within the timeout.  Assume it's a GUI app
        logger.debug('This seems to be a GUI application.')
        self.gui_app = True
        try:
            runner_watchcpu = str(self.config['runner']['watchcpu']).lower()
            debugger_watchcpu = runner_watchcpu
        except KeyError:
            self.config['runner']['watchcpu'] = 'auto'
            self.config['debugger']['watchcpu'] = 'auto'
            runner_watchcpu = 'auto'
            debugger_watchcpu = 'auto'
        if runner_watchcpu == 'auto':
            logger.debug('Enabling runner CPU monitoring for dynamic timeout')
            self.config['runner']['watchcpu'] = True
            logger.debug(
                'kill runner watchcpu: %s', self.config['runner']['watchcpu'])
        if debugger_watchcpu == 'auto':
            logger.debug(
                'Enabling debugger CPU monitoring for dynamic timeout')
            self.config['debugger']['watchcpu'] = True
            logger.debug(
                'kill debugger watchcpu: %s', self.config['debugger']['watchcpu'])
        logger.debug('kill %s', p)
        p.kill()

    def _start_buttonclicker(self):
        if self.use_buttonclicker:
            rootpath = os.path.dirname(sys.argv[0])
            buttonclicker = os.path.join(
                rootpath, 'buttonclicker', 'buttonclicker.exe')
            os.startfile(buttonclicker)  # @UndefinedVariable

    def _stop_buttonclicker(self):
        if self.use_buttonclicker:
            os.system('taskkill /im buttonclicker.exe')

    def _do_iteration(self, seedfile, range_obj, seednum):
        # use a with...as to ensure we always hit
        # the __enter__ and __exit__ methods of the
        # newly created WindowsIteration()
        with WindowsIteration(seedfile=seedfile,
                              seednum=seednum,
                              workdirbase=self.working_dir,
                              outdir=self.outdir,
                              sf_set=self.seedfile_set,
                              uniq_func=self._testcase_is_unique,
                              config=self.config,
                              fuzzer_cls=self.fuzzer_cls,
                              runner_cls=self.runner_cls,
                              debug=self.debug,
                              ) as iteration:
            try:
                iteration()
            except FuzzerExhaustedError:
                # Some fuzzers run out of things to do. They should
                # raise a FuzzerExhaustedError when that happens.
                logger.info(
                    'Done with %s, removing from set', seedfile.basename)
                self.seedfile_set.remove_file(seedfile)

        if not seednum % self.status_interval:
            logger.info('Iteration: %d crashes found: %d', self.current_seed,
                        len(self.testcases_seen))
