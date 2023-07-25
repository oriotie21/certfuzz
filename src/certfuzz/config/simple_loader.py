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
Created on Jan 13, 2016

@author: adh
'''
import logging
import yaml
import os
from errors import ConfigError
from certfuzz.helpers.misc import fixup_path, quoted
from string import Template
from copy import deepcopy

logger = logging.getLogger(__name__)

def load_config(yaml_file):
    '''
    Reads config from yaml_file, returns dict
    :param yaml_file: path to a yaml file containing the configuration
    '''
    with open(yaml_file, 'rb') as f:
        cfg = yaml.load(f)

    # yaml.load returns None if the file is empty. We need to raise an error
    if cfg is None:
        raise(ConfigError, 'Config file was empty')

    # add the file timestamp so we can tell if it changes later
    cfg['config_timestamp'] = os.path.getmtime(yaml_file)

    return cfg

def fixup_config(cfg):
    '''
    Substitutes program name into command line template
    returns modified dict
    '''
    # copy the dictionary
    cfgdict = deepcopy(cfg)
    # fix target program path
    cfgdict['target']['program'] = fixup_path(cfgdict['target']['program'])

    quoted_prg = quoted(cfgdict['target']['program'])
    quoted_sf = quoted('$SEEDFILE')
    t = Template(cfgdict['target']['cmdline_template'])
    intermediate_t = t.safe_substitute(PROGRAM=quoted_prg, SEEDFILE=quoted_sf)
    cfgdict['target']['cmdline_template'] = Template(intermediate_t)

    for k, v in cfgdict['directories'].iteritems():
        cfgdict['directories'][k] = fixup_path(v)

    if 'analyzer' not in cfgdict: cfgdict['analyzer'] = {}

    return cfgdict

def load_and_fix_config(yaml_file):
    return fixup_config(load_config(yaml_file))
