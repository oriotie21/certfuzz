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

import logging
import random

from certfuzz.fuzzers.fuzzer_base import MinimizableFuzzer
from certfuzz.fuzzers.fuzzer_base import is_fuzzable as _fuzzable

logger = logging.getLogger(__name__)

def fuzz(fuzz_input=None, seed_val=None, jump_idx=None, ratio_min=0.0,
         ratio_max=1.0, range_list=None, fuzzable_chars=None):
    '''
    Twiddle bytes of input and return output
    '''
    logging.debug('fuzz params: %d %d %f %f %s', seed_val, jump_idx, ratio_min, ratio_max, range_list)
    if seed_val is not None:
        random.seed(seed_val)
    if jump_idx is not None:
        random.jumpahead(jump_idx)

    ratio = random.uniform(ratio_min, ratio_max)
    inputlen = len(fuzz_input)

    chunksize = 2 ** 19  # 512k
    logger.debug('ratio=%f len=%d', ratio, inputlen)
    if range_list:
        chunksize = inputlen
    for chunk_start in xrange(0, inputlen, chunksize):
        chunk_end = min(chunk_start + chunksize, inputlen)
        chunk_len = chunk_end - chunk_start
        if range_list:
            chooselist = [x for x in xrange(inputlen) if _fuzzable(x, range_list)]
        else:
            chooselist = xrange(chunk_len)
        if fuzzable_chars is not None:
            chooselist = [x for x in chooselist if fuzz_input[x + chunk_start] in fuzzable_chars]
        
        nbytes_to_fuzz = int(round(ratio * len(chooselist)))
        bytes_to_fuzz = random.sample(chooselist, nbytes_to_fuzz)
        for idx in bytes_to_fuzz:
            offset = chunk_start + idx
            fuzz_input[offset] = random.getrandbits(8)
    return fuzz_input

class ByteMutFuzzer(MinimizableFuzzer):
    '''
    This fuzzer module randomly selects bytes in an input file and assigns
    them random values. The percent of the selected bytes can be tweaked by
    min_ratio and max_ratio. range_list specifies a range in the file to fuzz.
    Roughly similar to cmiller's 5 lines o' python, except clearly less space
    efficient.
    '''
    fuzzable_chars = None

    def _fuzz(self):
        self.range = self.sf.rangefinder.next_item()
        range_list = self.options.get('range_list')

        self.output = fuzz(fuzz_input=self.input,
                           seed_val=self.rng_seed,
                           jump_idx=self.iteration,
                           ratio_min=self.range.min,
                           ratio_max=self.range.max,
                           range_list=range_list,
                           fuzzable_chars=self.fuzzable_chars,
                           )

_fuzzer_class = ByteMutFuzzer
