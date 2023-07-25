
#-*- coding:utf-8 -*-
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
Created on Mar 16, 2011

@organization: cert.org
'''
import hashlib
import os

from certfuzz.fuzztools.filetools import check_zip_content, read_bin_file

class BasicFile(object):
    '''
    Object to contain basic info about file: path, basename, dirname, len, md5
    '''

    #[modified]
    def __init__(self, path, child=""):

        self.path = path
        (self.dirname, self.basename) = os.path.split(self.path)
        if '.' in self.basename:
            # Split on first '.' to retain multiple dotted extensions
            self.root = self.basename.split('.', 1)[0]
            ext = '.' + self.basename.split('.', 1)[1]
            # Get rid of any spaces in extension
            self.ext = ext.replace(' ', '')
        else:
            self.root = self.basename
            self.ext = ''

        self.len = None
        self.md5 = None
        self.bitlen = None
        self.is_zip = False
        self.child = child
        self.refresh()

    def refresh(self):
        if self.exists():
            content = self.read()
            self.len = len(content)
            self.bitlen = 8 * self.len
            self.md5 = hashlib.md5(content).hexdigest()
            self.sha1 = hashlib.sha1(content).hexdigest()
            self.is_zip = check_zip_content(content)

    def read(self):
        '''
        Returns the contents of the file.
        '''
        '''
        if directory-based seedfile, get filename from child, which will be mutated
        '''
        _path = self.path
        if not os.path.isfile(self.path): #is project folder
            self.path = os.path.join(self.path, self.child)
        r = read_bin_file(self.path, child=self.child)
        self.path = _path
        return r

    def exists(self):
        return os.path.exists(self.path)

    def __repr__(self):
        return '%s' % self.__dict__

    def to_FileDoc(self, doc=None):
        from certfuzz.db.couchdb.datatypes.file_doc import FileDoc
        if doc is None:
            doc = FileDoc()
        doc.id = self.sha1
        doc.filename = self.basename
        doc.extension = self.ext
        doc.sha1 = self.sha1
        doc.size_in_bytes = self.len
        return doc
