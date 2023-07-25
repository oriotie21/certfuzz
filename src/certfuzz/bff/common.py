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
Created on Apr 3, 2014

@author: adh
'''
import logging
from logging.handlers import RotatingFileHandler
import os
import sys

from certfuzz.fuzztools.filetools import mkdir_p

from certfuzz.bff.errors import BFFerror
from certfuzz.version import __version__
import argparse

logger = logging.getLogger(__name__)

def add_log_handler(log_obj, level, hdlr, formatter):
    hdlr.setLevel(level)
    hdlr.setFormatter(formatter)
    log_obj.addHandler(hdlr)

def setup_debugging():
    logger.debug('Instantiating embedded rpdb2 debugger with password "bff"...')
    try:
        import rpdb2
        rpdb2.start_embedded_debugger("bff", timeout=5.0)
    except ImportError:
        logger.debug('Skipping import of rpdb2. Is Winpdb installed?')

    logger.debug('Enabling heapy remote monitoring...')
    try:
        from guppy import hpy  # @UnusedImport
        import guppy.heapy.RM  # @UnusedImport
    except ImportError:
        logger.debug('Skipping import of heapy. Is Guppy-PE installed?')

class BFF(object):
    def __init__(self, config_path=None, campaign_class=None):
        self.config_path = config_path
        self.campaign_class = campaign_class

        self._logdir = 'log'
        self._logfile = os.path.abspath(os.path.join(self._logdir, 'bff.log'))
        self.logfile = None
        self.log_level = logging.INFO

    def __enter__(self):
        self._parse_args()
        self._process_args()

        self._setup_logging()

        if self.args.debug:
            setup_debugging()

        return self.go

    def __exit__(self, etype, value, traceback):
        pass

    def _parse_args(self):
        parser = argparse.ArgumentParser(description='CERT Basic Fuzzing Framework {}'.format(__version__))

        group = parser.add_mutually_exclusive_group()
        group.add_argument('-d', '--debug', dest='debug', action='store_true',
                          help='Set logging to DEBUG and enable additional debuggers if available')
        group.add_argument('-q', '--quiet', dest='quiet', action='store_true',
                          help='Set logging to WARNING level')
        group.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                          help='Set logging to INFO level')

        parser.add_argument('-c', '--config', dest='configfile', type=str, help='Path to config file',
                          default=self.config_path, metavar='FILE')
        parser.add_argument('-l', '--logfile', dest='logfile', type=str, default=self._logfile,
                          help='Path to log file', metavar='FILE')
        parser.add_argument('-r', '--result-dir', dest='resultdir', type=str,
                          default=None,
                          help='Path to result directory (overrides config)', metavar='DIR')

        self.args = parser.parse_args()

    def _process_args(self):
        # set logfile destination
        self.logfile = self.args.logfile

        # set log level
        if self.args.debug:
            self.log_level = logging.DEBUG
        elif self.args.verbose:
            self.log_level = logging.INFO
        elif self.args.quiet:
            self.log_level = logging.WARNING

    def _setup_logging(self):
        logdir = os.path.abspath(os.path.dirname(self.logfile))
        mkdir_p(logdir)

        root_logger = logging.getLogger()
        root_logger.setLevel(self.log_level)

        fmt = logging.Formatter('%(asctime)s %(levelname)s %(name)s - %(message)s')

        handlers = []
        handlers.append(logging.StreamHandler())
        handlers.append(RotatingFileHandler(self.logfile,
                        mode='w',
                        maxBytes=1e7,
                        backupCount=5)
                        )

        for handler in handlers:
            add_log_handler(root_logger, self.log_level, handler, fmt)

    def go(self):
        logger.info('Welcome to %s version %s', sys.argv[0], __version__)

        if self.campaign_class is None:
            raise BFFerror('Campaign class is undefined')

        logger.info('Creating campaign')
        with self.campaign_class(config_file=self.args.configfile,
                      result_dir=self.args.resultdir,
                      debug=self.args.debug) as campaign:
            logger.info('Starting campaign')
            campaign.go()

        logger.info('Campaign complete')
