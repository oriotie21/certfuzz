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
Created on Oct 25, 2010

@organization: cert.org
'''

import logging
import platform

import subprocess

system = platform.system()

supported_systems = ['Linux']

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class WatchDog:
    def __init__(self, f, timeout):
        self.file = f
        self.timeout = timeout

        # we're just going to overwrite /etc/watchdog.conf
        # hope that's okay
        self.template = 'sudo sh -c "echo file={} > /etc/watchdog.conf'
        self.template += ' && echo change={} >> /etc/watchdog.conf'
        self.template += ' && /etc/init.d/watchdog restart"'

        self.cmdline = None

    def __enter__(self):
        self._set_cmdline()
        return self.go

    def __exit__(self, etype, value, traceback):
        handled = False

        if etype is subprocess.CalledProcessError:
            logger.warning('WatchDog startup failed: %s', value)
            handled = True

        return handled

    def _set_cmdline(self):
        self.cmdline = self.template.format(self.file, self.timeout)

    def go(self):
        '''
        Sets a watchdog timer with <timeout>
        '''
        # short-circuit on unsupported systems
        if not system in supported_systems:
            logger.warning('WatchDog does not support %s', system)
            return

        subprocess.check_call(self.cmdline, shell=True)
