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
Created on Dec 8, 2010

@organization: cert.org
'''
import logging
import math

from certfuzz.fuzztools.errors import RangeFinderError
from certfuzz.fuzztools.range import Range
from certfuzz.scoring.multiarmed_bandit.bayesian_bandit import BayesianMultiArmedBandit as MultiArmedBandit

range_scale_factor = (math.sqrt(5) + 1.0) / 2.0

logger = logging.getLogger(__name__)

class RangeFinder(MultiArmedBandit):
    '''
    Provides facilities to maintain:
        1. a set of ranges (typically from min=1.0/filesize to max=1.0-1.0/filesize)
        2. scores for each range
        3. a probability distribution across all ranges
    as well as a picker method to randomly choose a range based on the probability distribution.
    '''

    def __init__(self, low, high):
        MultiArmedBandit.__init__(self)

        self.min = low
        self.max = high
        # the lowest range must have at least abs_min as its max
        # so that we don't wind up fuzzing a range of 0.000000:0.000000
        self.abs_min = 0.000001
        if self.max < self.min:
            raise RangeFinderError('max cannot be less than min')

        self._set_ranges()

    def _exp_range(self, low, factor):
        high = low * factor
        # don't overshoot the high
        if high > self.max:
            high = self.max
        # don't undershoot abs_min
        if high < self.abs_min:
            high = self.abs_min
        return high

    def _set_ranges(self):
        rmin = self.min
        ranges = []
        while rmin < self.max:
            rmax = self._exp_range(rmin, range_scale_factor)
            ranges.append(Range(rmin, rmax))
            rmin = rmax

        # sometimes the last range might be smaller than the next to the last range
        # fix that if it happens
        (penultimate, ultimate) = ranges[-2:]
        if ultimate.span < penultimate.span:
            # create a new range to span both ranges
            merged_range = Range(penultimate.min, ultimate.max)
            # remove the last two ranges
            ranges = ranges[:-2]
            # and replace them with the merged range
            ranges.append(merged_range)

        for r in ranges:
            self.add_item(r.id, r)

    def next_item(self):
        return self.next()
