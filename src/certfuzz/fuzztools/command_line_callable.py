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
Created on Mar 6, 2013

@organization: cert.org
'''
import logging
import subprocess

logger = logging.getLogger(__name__)

class CommandLineCallable(object):
    '''
    Class intended mainly for binding a python API to an underlying command
    line utility.

    Intended use:
    class MyCLI(CommandLineCallable):
        def __init__(self,debug=False):
            CommandLineCallable.__init__(self,ignore_result=False)
            self.arg_pfx = ['mycli']
            if debug:
                self.arg_pfx.append('--debug')
        def cli_command(*extra_arg_list):
            args = ['cli_command']
            args.extend(extra_arg_list)
            self.call(args)
            if self.stderr:
                raise Exception('Something has gone wrong')

    The class above thus allows you to write:
    cli=MyCLI(debug=True)
    cli.cli_command('foo','bar')
    try:
        result = cli.stdout
    except:
        for line in cli.stderr.splitlines():
            logger.warning(line)
        raise

    Which would in turn invoke:
        $ mycli --debug cli_command foo bar
    Placing stdout into cli.stdout, and raising an exception if stderr is not
    empty.
    '''
    arg_pfx = []

    def __init__(self, ignore_result=False):
        self.stdout = ''
        self.stderr = ''
        if ignore_result:
            self.call = self._call
        else:
            self.call = self._call_stdout_stderr

    def _call(self, args):
        # TODO: do we need a p.wait() here?
        arglist = self.arg_pfx + args
        logger.debug(' '.join(arglist))
        subprocess.call(arglist)

    def _call_stdout_stderr(self, args):
        arglist = self.arg_pfx + args
        logger.debug(' '.join(arglist))
        p = subprocess.Popen(arglist,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        (self.stdout, self.stderr) = p.communicate()
