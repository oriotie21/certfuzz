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
Created on Jan 18, 2012

@organization: cert.org
'''
import re
import logging
from certfuzz.debuggers.output_parsers import DebuggerFile
from certfuzz.debuggers.output_parsers import regex as regex_base

from optparse import OptionParser

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)

# copy regexes
regex = dict(regex_base)
regex.update({
        'innermost_frame': re.compile(r'^#0.+'),
        'gdb_bt_threads': re.compile(r'^\[New Thread.+'),
        'konqi_bt_threads': re.compile(r'^\[Current thread is \d+\s\(Thread\s([0-9a-zA-Z]+).+\]$'),
        'bt_thread': re.compile(r'^Thread\s\d+\s.+:$'),
        'libc_location': re.compile(r'(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+Yes\s.+/libc[-.]'),
        'mapped_frame': re.compile(r'(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+Yes\s.+(/.+)'),
         })

class Konqifile(DebuggerFile):
    def __init__(self, path, exclude_unmapped_frames=True):
        self.has_threads = False
        self.crashing_frame = ''
        self.crashing_thread = ''
        self.on_crashing_thread = False
        self.has_proc_map = False
        self.dataformat = 'gdb'

        DebuggerFile.__init__(self, path, exclude_unmapped_frames)

    def backtrace_line(self, idx, l):
        self._look_for_crashing_thread(l)
        m = re.match(regex['bt_line'], l)
        if m and self.on_crashing_thread:
            item = m.group(1)  # sometimes gdb splits across lines
            # so get the next one if it looks like '<anything> at <foo>' or '<anything> from <foo>'
            next_idx = idx + 1
            while next_idx < len(self.lines):
                nextline = self.lines[next_idx]
                if re.match(regex['bt_line_basic'], nextline):
                    break
                elif re.search(regex['bt_line_from'], nextline) or re.search(regex['bt_line_at'], nextline):
                    if not "Quit anyway" in nextline:
                        item = ' '.join((item, nextline))
                next_idx += 1

            self.backtrace.append(item)
            logger.debug('Appending to backtrace: %s', item)

    def _process_lines(self):
        logger.debug('_process_lines')

        for idx, line in enumerate(self.lines):

            if not self.dataformat:
                self._look_for_dataformat(line)

            # Check to see if the input data has threads
            if not self.has_threads and not self.on_crashing_thread:
                self._look_for_threads(line)

            # If there are threads, look to see which crashed
            if not self.crashing_frame and self.has_threads:
                self._look_for_crashing_frame(line)
            # Otherwise, there's just one thread and it's the crashing one
            else:
                self.backtrace_line(idx, line)

            if not self.exit_code:
                self._look_for_exit_code(line)

            if not self.signal:
                self._look_for_signal(line)

            if self.is_crash:
                self._look_for_crash(line)

            if not self.is_debugbuild:
                self._look_for_debug_build(line)

            if not self.is_corrupt_stack:
                self._look_for_corrupt_stack(line)

            if not self.libc_start_addr:
                self._look_for_libc_location(line)

            if not self.has_proc_map:
                self._look_for_proc_map(line)

            self._look_for_registers(line)
            self._build_module_map(line)

        self._process_backtrace()

    def _look_for_debugger_missed_stack_corruption(self):
        if self.has_proc_map:
            start_bt_length = len(self.backtrace)
            while self.backtrace:
                # If the outermost backtrace frame isn't from a loaded module,
                # then we're likely dealing with stack corruption
                mapped_frame = False

                frame_address = self._get_frame_address(self.backtrace[-1])
                if frame_address:
                    mapped_frame = self._is_mapped_frame(frame_address)
                    if not mapped_frame:
                        self.debugger_missed_stack_corruption = True
                        # we can't use this line in a backtrace, so pop it
                        removed_bt_line = self.backtrace.pop()
                        logger.debug("GDB missed corrupt stack detection. Removing backtrace line: %s", removed_bt_line)
                    else:
                        # as soon as we hit a line that is a mapped
                        # frame, we're done trimming the backtrace
                        break
                else:
                    # if the outermost frame of the backtrace doesn't list a memory address,
                    # it's likely main(), which is fine.
                    break

            end_bt_length = len(self.backtrace)

            if start_bt_length and not end_bt_length:
                # Destroyed ALL the backtrace!
                self.total_stack_corruption = True
                logger.debug('Total stack corruption. No backtrace lines left.')
        else:
            logger.debug('No proc map available.  Cannot check for stack corruption')

    def _look_for_crashing_frame(self, line):
        m = re.match(regex['innermost_frame'], line)
        if m:
            self.crashing_frame = line
            logger.debug('Crashing frame: %s', self.crashing_frame)

    def _look_for_threads(self, line):
        logger.debug('Looking for threads...')
        m = re.match(regex['gdb_bt_threads'], line)
        if m:
            self.has_threads = True
            logger.debug('Threads detected (gdb)')
            return

        m = re.match(regex['konqi_bt_threads'], line)
        if m:
            self.has_threads = True
            self.dataformat = "konqi"
            self.crashing_thread = m.group(1)
            logger.debug('Threads detected (DrKonqi)')

    def _look_for_crashing_thread(self, line):
        if self.dataformat is 'gdb':
            m = re.match(regex['innermost_frame'], line)
            if m and self.crashing_frame in line:
                self.on_crashing_thread = True
                logger.debug('Found crashing thread! (gdb)')
            elif m and self.has_threads:
                self.on_crashing_thread = False
            elif m:
                self.on_crashing_thread = True
                logger.debug('No threads in this data...')
        elif self.dataformat is 'konqi':
            m = re.match(regex['bt_thread'], line)
            if m and self.crashing_thread in line:
                logger.debug('Found crashing thread! (konqi)')
                self.on_crashing_thread = True
            elif m:
                self.on_crashing_thread = False

    def _look_for_proc_map(self, line):
        '''
        Check to see if the input file has proc map information
        '''
        m = re.match(regex['mapped_frame'], line)
        if m:
            logger.debug('Found proc map information')
            # self.has_proc_map = True
            # Currently disabling proc map assisted parsing.  ABRT reports don't contain
            # the map for the current process.  Only loaded libraries!
            self.has_proc_map = False
        else:
            self.exclude_unmapped_frames = False

if __name__ == '__main__':
    # override the module loger with the root logger
    logger = logging.getLogger()

    hdlr = logging.StreamHandler()
    logger.addHandler(hdlr)

    parser = OptionParser()
    parser.add_option('', '--debug', dest='debug', action='store_true', help='Enable debug messages (overrides --verbose)')
    parser.add_option('', '--verbose', dest='verbose', action='store_true', help='Enable verbose messages')
    (options, args) = parser.parse_args()

    if options.debug:
        logger.setLevel(logging.DEBUG)
    elif options.verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)

    for f in args:
        k = Konqifile(f)
        print 'Signature=%s' % k.get_testcase_signature(5)
        if k.registers_hex.get('eip'):
            print 'EIP=%s' % k.registers_hex['eip']
