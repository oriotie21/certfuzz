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

"""This module runs cdb on a process and !exploitable on any exceptions.
"""
import ctypes
import logging
import os
from pprint import pformat
from subprocess import Popen
from threading import Timer
import time

from certfuzz.debuggers.debugger_base import Debugger as DebuggerBase
from certfuzz.debuggers.output_parsers.msec_file import MsecFile

import sys

if sys.platform.startswith('win'):
    import wmi

logger = logging.getLogger(__name__)

def factory(options):
    return MsecDebugger(options)

class MsecDebugger(DebuggerBase):
    _platform = 'Windows'
    _key = 'msec'
    _ext = 'msec'

    def __init__(self, program, cmd_args, outfile_base, timeout, watchcpu, exception_depth=0, cdb_command='!exploitable -v', debug_heap=False, ** options):
        DebuggerBase.__init__(
            self, program, cmd_args, outfile_base, timeout, **options)
        self.exception_depth = exception_depth
        self.watchcpu = watchcpu
        if watchcpu:
            self.wmiInterface = wmi.WMI()
        self.t = None
        self.savedpid = None
        self.cdb_command = cdb_command
        self.debugheap = debug_heap

    def kill(self, pid, returncode):
        """kill function for Win32"""
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(1, 1, pid)
        ret = kernel32.TerminateProcess(handle, returncode)
        kernel32.CloseHandle(handle)
        return (0 != ret)

    def debugger_app(self):
        '''
        Returns the name of the debugger application to use in this class
        '''
        typical = "C:\\Program Files\\Debugging Tools for Windows (x86)\\cdb.exe"
        if os.path.exists(typical):
            return typical
        return 'cdb'

    def debugger_test(self):
        '''
        Returns a command line (as list) that can be run via subprocess.call
        to confirm whether the debugger is on the path.
        '''
        return [self.debugger_app(), '-version']

    def _get_cmdline(self, outfile):
        cdb_command = '$$Found_with_CERT_BFF_2.8;r;%s;q' % self.cdb_command
        args = []
        args.append(self.debugger_app())
        args.append('-amsec.dll')
        if hasattr(self, 'debugheap') and self.debugheap:
            # do not use hd, xd options if debugheap is set
            pass
        else:
            args.extend(('-hd', '-xd', 'gp'))
        args.extend(('-logo', outfile))
        args.extend(('-xd', 'bpe', '-xd', 'wob', '-o', '-G', '-c'))
        for self.exception_depth in xrange(0, self.exception_depth):
            cdb_command = 'g;' + cdb_command
        args.append(cdb_command)
        args.append(self.program)
        args.extend(self.cmd_args)
        for l in pformat(args).splitlines():
            logger.debug('dbg_args: %s', l)
        return args

    def _find_debug_target(self, exename, trycount=5):
        pid = None
        attempts = 0
        foundpid = False

        if self.watchcpu:

            while attempts < trycount and not foundpid:
                for process in self.wmiInterface.Win32_Process(name=exename):
                    # TODO: What if there's more than one?
                    pid = process.ProcessID
                    logger.debug('Found %s PID: %s', exename, pid)
                    foundpid = True

                attempts += 1
                if not foundpid and attempts < trycount:
                    logger.debug('%s not seen yet. Retrying...', exename)
                    time.sleep(0.1)

            if not pid:
                logger.debug('Cannot find %s child process!', exename)
        return pid

    def run_with_timer(self):
        # TODO: replace this with subp.run_with_timer()
        exename = os.path.basename(self.program)
        process_info = {}
        child_pid = None
        done = False
        started = False

        args = self._get_cmdline(self.outfile)
        p = Popen(args, stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'),
                  universal_newlines=True)
        self.savedpid = p.pid

        child_pid = self._find_debug_target(exename, trycount=5)
        if child_pid is None and self.watchcpu:
            logger.debug('Bailing on debugger iteration')
            self.kill(self.savedpid, 99)
            return

        # create a timer that calls kill() when it expires
        self.t = Timer(self.timeout, self.kill, args=[self.savedpid, 99])
        self.t.start()
        if self.watchcpu:
            # This is a race.  In some cases, a GUI app could be done before we can even measure it
            # TODO: Do something about it
            while p.poll() is None and not done and child_pid:
                for proc in self.wmiInterface.Win32_PerfRawData_PerfProc_Process(IDProcess=child_pid):
                    n1, d1 = long(proc.PercentProcessorTime), long(
                        proc.Timestamp_Sys100NS)
                    n0, d0 = process_info.get(child_pid, (0, 0))
                    try:
                        percent_processor_time = (
                            float(n1 - n0) / float(d1 - d0)) * 100.0
                    except ZeroDivisionError:
                        percent_processor_time = 0.0
                    process_info[child_pid] = (n1, d1)
                    logger.debug(
                        'Process %s CPU usage: %s', child_pid, percent_processor_time)
                    if percent_processor_time < 0.0000000001:
                        if started:
                            logger.debug(
                                'killing cdb session for %s due to CPU inactivity', child_pid)
                            done = True
                            self.kill(self.savedpid, 99)
                    else:
                        # Detected CPU usage. Now look for it to drop near zero
                        started = True

                if not done:
                    time.sleep(0.2)
        else:
            p.wait()
        self.t.cancel()

    def go(self):
        """run cdb and process output"""
        # For exceptions beyond the first one, put the handled exception number
        # in the name
        if self.exception_depth > 0:
            self.outfile = os.path.splitext(self.outfile)[
                0] + '.e' + str(self.exception_depth) + os.path.splitext(self.outfile)[1]
        self.run_with_timer()
        if not os.path.exists(self.outfile):
            # touch it if it doesn't exist
            open(self.outfile, 'w').close()

        parsed = MsecFile(self.outfile)

        for l in pformat(parsed.__dict__).splitlines():
            logger.debug('parsed: %s', l)
        return parsed

    def __exit__(self, etype, value, traceback):
        if self.t:
            logger.debug('Canceling timer...')
            self.t.cancel()

# END MsecDebugger
