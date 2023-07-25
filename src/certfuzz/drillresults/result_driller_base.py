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
Created on Jul 2, 2014

@organization: cert.org
'''
import abc
import logging
import os
import re

import cPickle as pickle
from certfuzz.drillresults.errors import DrillResultsError
from certfuzz.drillresults.errors import TestCaseBundleError

logger = logging.getLogger(__name__)

regex = {
    'dr_score': re.compile('.+ - Exploitability rank: (\d+)')
}

class ResultDriller(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self,
                 ignore_jit=False,
                 base_dir='../results',
                 force_reload=False,
                 report_all=False):
        self.ignore_jit = ignore_jit
        self.base_dir = base_dir
        self.tld = None
        self.force = force_reload
        self.report_all = report_all

        if report_all:
            self.max_score = None
        else:
            self.max_score = 70

        self.pickle_file = os.path.join('fuzzdir', 'drillresults.pkl')
        self.cached_testcases = None
        self.testcase_bundles = []
        self.dr_outputs = {}
        self.dr_scores = {}
        self.dr_paths = {}

    def __enter__(self):
        return self

    def __exit__(self, etype, value, traceback):
        handled = False

        if etype is DrillResultsError:
            print "{}: {}".format(etype.__name__, value)
            handled = True

        return handled

    @abc.abstractmethod
    def _platform_find_testcases(self, crash_hash):
        pass

    def _load_dr_output(self, crash_hash, drillresults_file):
        logger.debug(
            'Loading precalculated drillresults output from %s' % drillresults_file)
        dr_output = ''
        with open(drillresults_file, 'r') as f:
            dr_output = f.read()
        self.dr_outputs[crash_hash] = dr_output
        self.dr_scores[crash_hash] = self._get_dr_score(dr_output)
        self.dr_paths[crash_hash] = os.path.dirname(drillresults_file)
        return

    def store_dr_output(self, crash_hash, dr_output, score):
        logger.debug(
            'Storing recalculated drillresults output for %s' % crash_hash)
        self.dr_scores[crash_hash] = score
        return

    def process_testcases(self):
        '''
        Crawls self.tld looking for crash directories to process. Puts a list
        of tuples into self.testcase_bundles.
        '''
        # Walk the results directory
        for root, dirs, files in os.walk(self.tld):
            logger.debug('Looking for testcases in %s', root)
            dir_basename = os.path.basename(root)
            try:
                self._platform_find_testcases(
                    dir_basename, files, root, force=self.force)
            except TestCaseBundleError as e:
                logger.warning('Skipping %s: %s', dir_basename, e)
                continue

    def _check_dirs(self):
        check_dirs = [self.base_dir, 'results', 'crashers']
        for d in check_dirs:
            if os.path.isdir(d):
                self.tld = d
                logger.debug('found dir: %s', self.tld)
                return
        # if you got here, none of them exist
        raise DrillResultsError(
            'None of {} appears to be a dir'.format(check_dirs))

    def load_cached(self):
        if self.force:
            logger.info('--force option used, ignoring cached results')
            return

        try:
            with open(self.pickle_file, 'rb') as pkl_file:
                self.cached_testcases = pickle.load(pkl_file)
        except (IOError, EOFError):
            # No cached results
            pass

    @property
    def crash_scores(self):
        return dict([(tcb.crash_hash, tcb.score) for tcb in self.testcase_bundles])

    def _get_dr_score(self, dr_output):
        firstline = dr_output.splitlines()[0]
        m = regex['dr_score'].match(firstline)
        score = int(m.group(1))
        return score

    def print_crash_report(self, crash_key, score, details):
        #        details = self.results[crash_key]
        print '\n%s - Exploitability rank: %s' % (crash_key, score)
        print 'Fuzzed file: %s' % details['fuzzedfile']
        for exception in details['exceptions']:
            shortdesc = details['exceptions'][exception]['shortdesc']
            eiftext = ''
            efa = '0x' + details['exceptions'][exception]['efa']
            if details['exceptions'][exception]['EIF']:
                eiftext = " *** Byte pattern is in fuzzed file! ***"
            print 'exception %s: %s accessing %s  %s' % (exception, shortdesc, efa, eiftext)
            if details['exceptions'][exception]['instructionline']:
                print details['exceptions'][exception]['instructionline']
            module = details['exceptions'][exception]['pcmodule']
            if module == 'unloaded':
                if not self.ignore_jit:
                    print 'Instruction pointer is not in a loaded module!'
            else:
                print 'Code executing in: %s' % module

    @property
    def sorted_crashes(self):
        return sorted(self.crash_scores.iteritems(), key=lambda(k, v): (v, k))

    @property
    def sorted_drillresults_output(self):
        return sorted(self.dr_scores.iteritems(), key=lambda(k, v): (v, k))

    def print_drillresults_file(self, crash_key):
        ff_line_indicator = 'Fuzzed file: '
        for line in self.dr_outputs[crash_key].splitlines():
            if line.startswith(ff_line_indicator):
                pathname = line.replace(ff_line_indicator, '')
                fuzzedfile = os.path.basename(pathname)
                realdir = self.dr_paths[crash_key]
                fixed_ff_path = os.path.join(realdir, fuzzedfile)
                print ('%s%s' % (ff_line_indicator, fixed_ff_path))
            else:
                print line
        print ''

    def print_reports(self):
        results = dict([(tcb.crash_hash, tcb.details)
                        for tcb in self.testcase_bundles])
        print "--- Interesting crashes ---\n"

        if len(self.dr_scores) > 0:
            # We're using existing .drillresults files
            for crash_key, score in self.sorted_drillresults_output:
                # print('crash_key: %s, score: %s' % (crash_key, score))
                if score > self.max_score:
                    # skip test cases with scores above our max
                    continue
                self.print_drillresults_file(crash_key)
            return

        for crash_key, score in self.sorted_crashes:
            if self.max_score is not None:
                if score > self.max_score:
                    # skip test cases with scores above our max
                    continue

            details = results[crash_key]
            try:
                self.print_crash_report(crash_key, score, details)
            except KeyError as e:
                logger.warning(
                    'Tescase %s is missing information: %s', crash_key, e)

    def cache_results(self):
        pkldir = os.path.dirname(self.pickle_file)
        if not os.path.exists(pkldir):
            os.makedirs(pkldir)
        with open(self.pickle_file, 'wb') as pkl_file:
            pickle.dump(self.testcase_bundles, pkl_file, -1)

    def drill_results(self):
        logger.debug('drill_results')
        self._check_dirs()
        self.load_cached()
        self.process_testcases()
        self.print_reports()
        self.cache_results()
