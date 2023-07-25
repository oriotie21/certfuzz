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

"""This 'just in time debugger' module terminates the "fuzzjob" job object
when called with an ACCESS_VIOLATION return code as a signal to the main
fuzzer that an exception occurred.

"""
from ctypes import windll, byref
from ctypes.wintypes import HANDLE, BOOL, LPCWSTR
import sys

def main(pid=None):
    PROCESS_TERMINATE = 0x0001
    PROCESS_QUERY_INFORMATION = 0x0400
    JOB_OBJECT_ALL_ACCESS = 0x1F001F
    hProc = HANDLE()
    result = BOOL()
    kernel32 = windll.kernel32
    hProc = kernel32.OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION,
        None, pid)
    hJobObject = kernel32.OpenJobObjectW(JOB_OBJECT_ALL_ACCESS, 1,
        LPCWSTR("fuzzjob"))
    if hJobObject == None:
        # this process is not in the fuzzjob, bail
        exit()
    kernel32.IsProcessInJob(hProc, hJobObject, byref(result))
    if result.value:
        kernel32.TerminateJobObject(hJobObject, 0xC0000005)

#else:
#    pass

if __name__ == "__main__":
    # crash pid
    pid = int(sys.argv[1])
    main(pid)
