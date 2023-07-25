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

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

from ctypes import c_void_p, POINTER, sizeof, Structure, windll, WinError, WINFUNCTYPE, addressof, c_size_t, c_ulong
from ctypes.wintypes import BOOL, BYTE, DWORD, HANDLE, LARGE_INTEGER

LPVOID = c_void_p
LPDWORD = POINTER(DWORD)
SIZE_T = c_size_t
ULONG_PTR = POINTER(c_ulong)

# A ULONGLONG is a 64-bit unsigned integer.
# Thus there are 8 bytes in a ULONGLONG.
# XXX why not import c_ulonglong ?
ULONGLONG = BYTE * 8

class IO_COUNTERS(Structure):
    # The IO_COUNTERS struct is 6 ULONGLONGs.
    # TODO: Replace with non-dummy fields.
    _fields_ = [('dummy', ULONGLONG * 6)]

class JOBOBJECT_BASIC_ACCOUNTING_INFORMATION(Structure):
    _fields_ = [('TotalUserTime', LARGE_INTEGER),
                ('TotalKernelTime', LARGE_INTEGER),
                ('ThisPeriodTotalUserTime', LARGE_INTEGER),
                ('ThisPeriodTotalKernelTime', LARGE_INTEGER),
                ('TotalPageFaultCount', DWORD),
                ('TotalProcesses', DWORD),
                ('ActiveProcesses', DWORD),
                ('TotalTerminatedProcesses', DWORD)]

class JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION(Structure):
    _fields_ = [('BasicInfo', JOBOBJECT_BASIC_ACCOUNTING_INFORMATION),
                ('IoInfo', IO_COUNTERS)]

# see http://msdn.microsoft.com/en-us/library/ms684147%28VS.85%29.aspx
class JOBOBJECT_BASIC_LIMIT_INFORMATION(Structure):
    _fields_ = [('PerProcessUserTimeLimit', LARGE_INTEGER),
                ('PerJobUserTimeLimit', LARGE_INTEGER),
                ('LimitFlags', DWORD),
                ('MinimumWorkingSetSize', SIZE_T),
                ('MaximumWorkingSetSize', SIZE_T),
                ('ActiveProcessLimit', DWORD),
                ('Affinity', ULONG_PTR),
                ('PriorityClass', DWORD),
                ('SchedulingClass', DWORD)
                ]

class JOBOBJECT_ASSOCIATE_COMPLETION_PORT(Structure):
    _fields_ = [('CompletionKey', c_ulong),
                ('CompletionPort', HANDLE)]

# see http://msdn.microsoft.com/en-us/library/ms684156%28VS.85%29.aspx
class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(Structure):
    _fields_ = [('BasicLimitInformation', JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ('IoInfo', IO_COUNTERS),
                ('ProcessMemoryLimit', SIZE_T),
                ('JobMemoryLimit', SIZE_T),
                ('PeakProcessMemoryUsed', SIZE_T),
                ('PeakJobMemoryUsed', SIZE_T)]

# These numbers below come from:
# http://msdn.microsoft.com/en-us/library/ms686216%28v=vs.85%29.aspx
JobObjectAssociateCompletionPortInformation = 7
JobObjectBasicAndIoAccountingInformation = 8
JobObjectExtendedLimitInformation = 9

class JobObjectInfo(object):
    mapping = { 'JobObjectBasicAndIoAccountingInformation': 8,
                'JobObjectExtendedLimitInformation': 9,
                'JobObjectAssociateCompletionPortInformation': 7
                }
    structures = {
                   7: JOBOBJECT_ASSOCIATE_COMPLETION_PORT,
                   8: JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION,
                   9: JOBOBJECT_EXTENDED_LIMIT_INFORMATION
                   }
    def __init__(self, _class):
        if isinstance(_class, basestring):
            assert _class in self.mapping, 'Class should be one of %s; you gave %s' % (self.mapping, _class)
            _class = self.mapping[_class]
        assert _class in self.structures, 'Class should be one of %s; you gave %s' % (self.structures, _class)
        self.code = _class
        self.info = self.structures[_class]()

QueryInformationJobObjectProto = WINFUNCTYPE(
    BOOL,        # Return type
    HANDLE,      # hJob
    DWORD,       # JobObjectInfoClass
    LPVOID,      # lpJobObjectInfo
    DWORD,       # cbJobObjectInfoLength
    LPDWORD      # lpReturnLength
    )

QueryInformationJobObjectFlags = (
    (1, 'hJob'),
    (1, 'JobObjectInfoClass'),
    (1, 'lpJobObjectInfo'),
    (1, 'cbJobObjectInfoLength'),
    (1, 'lpReturnLength', None)
    )

_QueryInformationJobObject = QueryInformationJobObjectProto(
    ('QueryInformationJobObject', windll.kernel32),
    QueryInformationJobObjectFlags
    )

class SubscriptableReadOnlyStruct(object):
    def __init__(self, struct):
        self._struct = struct

    def _delegate(self, name):
        result = getattr(self._struct, name)
        if isinstance(result, Structure):
            return SubscriptableReadOnlyStruct(result)
        return result

    def __getitem__(self, name):
        match = [fname for fname, ftype in self._struct._fields_
                 if fname == name]
        if match:
            return self._delegate(name)
        raise KeyError(name)

    def __getattr__(self, name):
        return self._delegate(name)

def QueryInformationJobObject(hJob, JobObjectInfoClass):
    jobinfo = JobObjectInfo(JobObjectInfoClass)
    result = _QueryInformationJobObject(
        hJob=hJob,
        JobObjectInfoClass=jobinfo.code,
        lpJobObjectInfo=addressof(jobinfo.info),
        cbJobObjectInfoLength=sizeof(jobinfo.info)
        )
    if not result:
        raise WinError()
    return SubscriptableReadOnlyStruct(jobinfo.info)
