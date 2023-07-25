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
Created on Oct 5, 2010

@organization: cert.org@cert.org

Provides the ability to calculate byte-wise or bit-wise Hamming Distance
between objects. P
'''
import itertools
import os

from certfuzz.fuzztools.filetools import get_zipcontents
from certfuzz.tools import path

def vector_compare(v1, v2):
    '''
    Given two sparse vectors (lists of indices whose value is 1), return the distance between them
    '''
    vdict = {}

    for v in v1, v2:
        for idx in v:
            if vdict.get(idx):
                vdict[idx] += 1
            else:
                vdict[idx] = 1

    distance = 0
    for val in vdict.values():
        if val == 1:
            distance += 1

    return distance

def bytemap(s1, s2):
    '''
    Given two strings of equal length, return the indices of bytes that differ.
    '''
    assert len(s1) == len(s2)
    delta = []
    for idx, (c1, c2) in enumerate(itertools.izip(s1, s2)):
        if c1 != c2:
            delta.append(idx)
    return delta

def bytewise_hd(s1, s2):
    '''
    Compute the byte-wise Hamming Distance between two strings. Returns
    the distance as an int.
    '''
    assert len(s1) == len(s2)
    return sum(ch1 != ch2 for ch1, ch2 in itertools.izip(s1, s2))

def bytewise_hamming_distance(file1, file2, child=""):
    '''
    Given the names of two files, compute the byte-wise Hamming Distance
    between them. Returns the distance as an int. Throws an AssertionError
    unless file1 and file2 are the same size.
    '''
    return _file_compare(bytewise_hd, False, file1, file2, child=child)

def bytewise_zip_hamming_distance(file1, file2):
    '''
    Given the names of two files, compute the byte-wise Hamming Distance
    between them. Returns the distance as an int. Throws an AssertionError
    unless file1 and file2 are the same size.
    '''
    return _file_compare(bytewise_hd, True, file1, file2)

def _file_compare(distance_function, comparezipcontents, file1, file2, child=""):
    if not comparezipcontents:
	#project file reading error fix
	if not os.path.isfile(file1):
	    file1 = path.join2(file1, child)
	if not os.path.isfile(file2):
	    file2 = path.join2(file2, child)

        assert os.path.getsize(file1) == os.path.getsize(file2)
	    
        with open(file1, 'rb') as f1:
            with open(file2, 'rb') as f2:
                # find the hamming distance for each byte
                distance = distance_function(f1.read(), f2.read())
    else:
        # Work with zip contents
        distance = distance_function(get_zipcontents(file1), get_zipcontents(file2))
    return distance

def bitwise_hd(x, y):
    '''
    Given two strings x and y, find the bitwise hamming distance
    between them. Returns the distance as an int. Throws an AssertionError
    unless x and y are the same size.
    '''
    assert len(x) == len(y)

    hd = 0
    for (a, b) in itertools.izip(x, y):
        a = ord(a)
        b = ord(b)

        v = a ^ b
        while v:
            v = v & (v - 1)
            hd += 1
    return hd

def bitwise_hamming_distance(file1, file2, child=""):
    '''
    Given the names of two files, compute the bit-wise Hamming Distance
    between them. Returns the distance as an int. Throws an AssertionError
    unless file1 and file2 are the same size.
    '''
    return _file_compare(bitwise_hd, False, file1, file2, child=child)

def bitwise_zip_hamming_distance(file1, file2, child=""):
    '''
    Given the names of two files, compute the bit-wise Hamming Distance
    between them. Returns the distance as an int. Throws an AssertionError
    unless file1 and file2 are the same size.
    '''
    return _file_compare(bitwise_hd, True, file1, file2, child=child)
