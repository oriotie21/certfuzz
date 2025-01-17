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

import collections
import logging
import zipfile

from certfuzz.fuzztools.filetools import check_zip_file, write_file
from certfuzz.fuzztools.filetools import exponential_backoff
from certfuzz.minimizer.minimizer_base import Minimizer as MinimizerBase
from certfuzz.minimizer.errors import WindowsMinimizerError
from certfuzz.debuggers.msec import MsecDebugger

logger = logging.getLogger(__name__)

class WindowsMinimizer(MinimizerBase):
    use_watchdog = False
    _debugger_cls = MsecDebugger

    def __init__(self, cfg=None, testcase=None, crash_dst_dir=None,
                 seedfile_as_target=False, bitwise=False, confidence=0.999,
                 logfile=None, tempdir=None, maxtime=3600, preferx=True,
                 keep_uniq_faddr=False, watchcpu=False):
        self.saved_arcinfo = None
        self.is_zipfile = check_zip_file(testcase.fuzzedfile.path)
        MinimizerBase.__init__(self, cfg, testcase, crash_dst_dir,
                               seedfile_as_target, bitwise, confidence,
                               logfile, tempdir, maxtime, preferx,
                               keep_uniq_faddr, watchcpu)

    def get_signature(self, dbg, backtracelevels):
        # get the basic signature
        crash_hash = MinimizerBase.get_signature(self, dbg, backtracelevels)
        if not crash_hash:
            self.signature = None
        else:
            crash_id_parts = [crash_hash]
            if self.testcase.keep_uniq_faddr and hasattr(dbg, 'faddr'):
                crash_id_parts.append(dbg.faddr)
            self.signature = '.'.join(crash_id_parts)
        return self.signature

    def _read_fuzzed(self):
        '''
        returns the contents of the fuzzed file
        '''
        # store the files in memory
        if self.is_zipfile:  # work with zip file contents, not the container
            logger.debug('Working with a zip file')
            return self._readzip(self.testcase.fuzzedfile.path)
        # otherwise just call the parent class method
        return MinimizerBase._read_fuzzed(self)

    def _read_seed(self):
        '''
        returns the contents of the seed file
        '''
        # we're either going to minimize to the seedfile, the metasploit
        # pattern, or a string of 'x's
        if self.is_zipfile and self.seedfile_as_target:
            return self._readzip(self.testcase.seedfile.path)
        # otherwise just call the parent class method
        return MinimizerBase._read_seed(self)

    def _readzip(self, filepath):
        # If the seed is zip-based, fuzz the contents rather than the container
        logger.debug('Reading zip file: %s', filepath)
        tempzip = zipfile.ZipFile(filepath, 'r')

        '''
        get info on all the archived files and concatentate their contents
        into self.input
        '''
        self.saved_arcinfo = collections.OrderedDict()
        unzippedbytes = ''
        logger.debug('Reading files from zip...')
        for i in tempzip.namelist():
            data = tempzip.read(i)

            # save split indices and compression type for archival
            # reconstruction. Keeping the same compression types is
            # probably unnecessary since it's the content that matters

            self.saved_arcinfo[i] = (len(unzippedbytes), len(data),
                                     tempzip.getinfo(i).compress_type)
            unzippedbytes += data
        tempzip.close()
        return unzippedbytes

    @exponential_backoff
    def _safe_createzip(self, filepath):
        tempzip = zipfile.ZipFile(filepath, 'w')
        return tempzip

    def _writezip(self):
        '''rebuild the zip file and put it in self.fuzzed
        Note: We assume that the fuzzer has not changes the lengths
        of the archived files, otherwise we won't be able to properly
        split self.fuzzed
        '''
        if self.saved_arcinfo is None:
            raise WindowsMinimizerError('_readzip was not called')

        filedata = ''.join(self.newfuzzed)
        filepath = self.tempfile

        logger.debug('Creating zip with mutated contents.')
        tempzip = self._safe_createzip(filepath)

        '''
        reconstruct archived files, using the same compression scheme as
        the source
        '''
        for name, info in self.saved_arcinfo.iteritems():
            # write out fuzzed file
            if info[2] == 0 or info[2] == 8:
                # Python zipfile only supports compression types 0 and 8
                compressiontype = info[2]
            else:
                logger.warning(
                    'Compression type %s is not supported. Overriding', info[2])
                compressiontype = 8
            tempzip.writestr(
                name, str(filedata[info[0]:info[0] + info[1]]), compress_type=compressiontype)
        tempzip.close()

    def _write_file(self):
        if self.is_zipfile:
            self._writezip()
        else:
            write_file(''.join(self.newfuzzed), self.tempfile,child=self.cfg['target']['mutate'])
