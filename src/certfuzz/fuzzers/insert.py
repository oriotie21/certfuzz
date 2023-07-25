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

"""
"""
import logging
from random import getrandbits

from certfuzz.fuzzers.fuzzer_base import Fuzzer
from certfuzz.fuzzers.errors import FuzzerExhaustedError

logger = logging.getLogger(__name__)

class InsertFuzzer(Fuzzer):
    '''
    This fuzzer module iterates through an input file, inserting a random byte
    between every byte position as it goes. E.g. insert before byte 0, before
    byte 1, etc.
    '''
    def _fuzz(self):
        '''
        Insert individual bytes of input and put output in self.output
        '''

        # TODO: add range list support to insert fuzzer
#        if self.options.get('use_range_list'):
#            bytes_to_fuzz = []
#            for (start, end) in self.options['range_list']:
#                    bytes_to_fuzz.extend(xrange(start, end + 1))
#        else:
#            bytes_to_fuzz = xrange(len(byte_buffer))
        bytes_to_fuzz = xrange(len(self.input))

        # we can calculate the byte to insert on based on the number of tries
        # on this seed file
        byte_pos = self.sf.tries
        byte_to_insert = getrandbits(8)

        if byte_pos < len(bytes_to_fuzz):
            self.input.insert(byte_pos, byte_to_insert)
        else:
            # indicate we didn't fuzz the file for this iteration
            raise FuzzerExhaustedError('Iteration exceeds available values')

        logger.debug('%s - inserted byte 0x%02x at 0x%02x', self.sf.basename,
                     byte_to_insert, byte_pos)

        self.output = self.input

_fuzzer_class = InsertFuzzer
