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
Created on Dec 9, 2011

@organization: cert.org
'''
# pylint complains about importing string and
# pylint: disable=w0142,w0402
import itertools
import re
import string

from certfuzz.fuzztools.filetools import get_newpath

def _pattern(iterables, length):
    pattern_parts = []
    l = 0
    for parts in itertools.cycle(itertools.product(*iterables)):
        # product returns a tuple
        l += len(parts)
        token = ''.join(parts)
        pattern_parts.append(token)

        if l >= length:
            # as soon as we exceed our desired length we can return,
            # slicing to fit as needed
            pattern = ''.join(pattern_parts)
            return pattern[:length]

def metasploit_pattern_orig(length):
    '''
    Returns the standard metasploit non-repeating pattern "Aa0Aa1...Zz9" as
    a string of the requested length. If length exceeds the pattern size, it
    will rollover ("...Zz9Aa0...") as many times as needed to meet the length
    requirement.

    The rollover occurs every 26*26*10*3 = 20,280 characters

    :param length: how long the string should be
    '''
    iterables = [string.ascii_uppercase,
                string.ascii_lowercase,
                string.digits]

    return _pattern(iterables, length)

def metasploit_pattern_extended(length):
    '''
    Returns the 'extended' metasploit non-repeating pattern
    "AAaa00...ZZzz99" as a string of the requested length. If length
    exceeds the pattern size, it will rollover ("...ZZzz99AAaa00...") as
    many times as needed to meet the length requirement.

    The rollover occurs every 26*26*26*26*10*10*6 = 274,185,600 characters

    :param length: how long the string should be
    '''

    iterables = [string.ascii_uppercase, string.ascii_uppercase,
                 string.ascii_lowercase, string.ascii_lowercase,
                 string.digits, string.digits]
    return _pattern(iterables, length)

def metasploit_pattern(length):
    return metasploit_pattern_extended(length)

def _enumerate_string(content, occurences):
    '''
    Replace each position in content given in occurences with
    a counter. Return byte array of the replaced content.

    Example:
    content = AAAAxxxAAAAxxxxxAAAAxAAAA
    occurrences = [0,7,16,21]
    result = 1AAAxxx2AAAxxxxx3AAAx4AAA
    '''
    counter = itertools.count()
    byte_buffer = bytearray(content)
    for pos, count in itertools.izip(occurences, counter):
        # turn the counter into a string
        substr = str(count)
        nbytes = len(substr)
        # replace the original bytes with the bytes of the counter string
        for offset in xrange(nbytes):
            p = pos + offset
            byte_buffer[p] = substr[offset]
    return byte_buffer

def enumerate_string(path=None, str_to_enum=None):
    '''
    Read file from path.ext and enumerate each occurrence of str_to_enum with
    a counter. Write result to path-enum.ext

    Example:
    file content = AAAAxxxAAAAxxxxxAAAAxAAAA
    str_to_enum = AAAA
    result = 0AAAxxx1AAAxxxxx2AAAx3AAA
    '''
    with open(path, 'rb') as f:
        content = f.read()

    newpath = get_newpath(oldpath=path, str_to_insert='-enum')

    # create a generator to find all start positions of the substring
    occurences = (m.start() for m in re.finditer(str_to_enum, content))

    newcontent = _enumerate_string(content, occurences)

    with open(newpath, 'wb') as f:
        f.write(newcontent)
    return newpath

if __name__ == '__main__':
    for i in range(100):
        print 'orig', i, metasploit_pattern_orig(i)
        print 'extd', i, metasploit_pattern_extended(i)
