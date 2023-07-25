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
Created on Jul 10, 2013

@organization: cert.org
'''

import os
import collections
import zipfile
from optparse import OptionParser

saved_arcinfo = collections.OrderedDict()

def readzip(filepath):
    global savedarcinfo
    # If the seed is zip-based, fuzz the contents rather than the container
    tempzip = zipfile.ZipFile(filepath, 'r')

    '''
    get info on all the archived files and concatentate their contents
    into self.input
    '''
    unzippedbytes = ''
    for i in tempzip.namelist():
        data = tempzip.read(i)

        # save split indices and compression type for archival reconstruction

        saved_arcinfo[i] = (len(unzippedbytes), len(data))
        unzippedbytes += data
    tempzip.close()
    return unzippedbytes

def main():
    global saved_arcinfo
    usage = 'usage: %prog zip1 zip2'
    parser = OptionParser(usage=usage)
    (options, args) = parser.parse_args()

    if len(args) != 2:
        parser.error('Incorrect number of arguments')
        return

    changedbytes = []
    changedfiles = []

    zip1 = args[0]
    zip2 = args[1]
    zip1bytes = readzip(zip1)
    zip2bytes = readzip(zip2)
    zip1len = len(zip1bytes)

    if zip1len != len(zip2bytes):
        print 'Zip contents are not the same size. Aborting.'

    for i in range(0, zip1len):
        if zip1bytes[i] != zip2bytes[i]:
#            print 'Zip contents differ at offset %s' % i
            changedbytes.append(i)

    for changedbyte in changedbytes:
        for name, info in saved_arcinfo.iteritems():
            startaddr = info[0]
            endaddr = info[0] + info[1]
            if startaddr <= changedbyte <= endaddr and name not in changedfiles:
                print '%s modified' % name
                changedfiles.append(name)
            #print '%s: %s-%s' %(name, info[0], info[0]+info[1])

if __name__ == '__main__':
    main()
