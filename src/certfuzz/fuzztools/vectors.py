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
Created on Feb 22, 2011

@organization: cert.org
'''
# from numpy import dot
# from numpy.linalg import norm
import math

def compare(d1, d2):
    '''
    Turn two dicts into vectors, then calculate their similarity
    @param d1: a dict with numeric values
    @param d2: a dict with numeric values
    '''

    # get the set of all keys for the two dicts
    k1 = set(d1.keys())
    k2 = set(d2.keys())
    keyset = k1.union(k2)

    # build vectors
    v1 = []
    v2 = []

    for k in keyset:
        v1.append(d1.get(k, 0))
        v2.append(d2.get(k, 0))

    return similarity(v1, v2)

def similarity(v1, v2):
    return cos(v1, v2)

def cos(v1, v2):
    assert len(v1) == len(v2), 'Cannot compare vectors of unequal length'
    dotproduct = float(dot(v1, v2))
    norm1 = float(norm(v1))
    norm2 = float(norm(v2))
    sim = dotproduct / (norm1 * norm2)
    sim = float('%.6f' % sim)  # fix for floating point very near 1.0 BFF-234
    assert 0 <= sim <= 1.0, 'Similarity out of range: %f' % sim

    return sim

def dot(v1, v2):
    '''
    Calculate the sum of the products of each term in v1 and v2
    @param v1:
    @param v2:
    '''
    assert len(v1) == len(v2), 'Vectors are different lengths'

    terms = zip(v1, v2)
    products = [float(x) * float(y) for (x, y) in terms]
    total = sum(products)
    return total

def norm(v):
    squares = [float(x) * float(x) for x in v]
    total = sum(squares)
    sqrt = math.sqrt(total)
    return sqrt

class Vector(object):
    def __init__(self, v):
        self.vector = v
