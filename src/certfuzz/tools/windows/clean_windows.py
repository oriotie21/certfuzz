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
Created on Feb 28, 2012

@author: adh
'''

import os
import pprint
import tempfile
import time
import re

defaults = {'config': 'configs/bff.yaml',
            'remove_results': False,
            'pretend': False,
            'retry': 3,
            'debug': False,
            'nuke': False,
          }

SLEEPTIMER = 0.5
BACKOFF_FACTOR = 2

def main():
    import optparse
    try:
        from certfuzz.fuzztools.filetools import delete_contents_of
        from certfuzz.config.simple_loader import load_and_fix_config
    except ImportError:
        # if we got here, we probably don't have .. in our PYTHONPATH
        import sys
        mydir = os.path.dirname(os.path.abspath(__file__))
        parentdir = os.path.abspath(os.path.join(mydir, '..'))
        sys.path.append(parentdir)
        from certfuzz.fuzztools.filetools import delete_contents_of
        from certfuzz.config.simple_loader import load_and_fix_config
        if not os.path.exists(defaults['config']):
            defaults['config'] = '../configs/bff.yaml'

    parser = optparse.OptionParser()
    parser.add_option('-c', '--config', dest='configfile', default=defaults['config'], metavar='FILE')
    parser.add_option('-p', '--pretend', dest='pretend', action='store_true', default=defaults['pretend'], help='Do not actually remove files')
    parser.add_option('-r', '--retry', dest='retries', default=defaults['retry'], type='int', metavar='INT')
    parser.add_option('', '--remove-results', dest='remove_results', action='store_true', default=defaults['remove_results'], help='Removes results dir contents')
    parser.add_option('', '--all', dest='nuke', action='store_true', default=defaults['nuke'], help='Equivalent to --remove-results')
    parser.add_option('', '--debug', dest='debug', action='store_true', default=defaults['debug'])
    options, _args = parser.parse_args()

    cfg_file = options.configfile
    config = load_and_fix_config(cfg_file)

    if options.debug:
        pprint.pprint(config)

    dirs = set()

    if options.nuke:
        options.remove_results = True

    dirs.add(os.path.abspath(config['directories']['working_dir']))
    campaign_id = config['campaign']['id']
    campaign_id_no_space = re.sub('\s', '_', campaign_id)
    dirs.add(os.path.join(os.path.abspath(config['directories']['results_dir']), campaign_id_no_space, 'seedfiles'))
    if options.remove_results:
        dirs.add(os.path.join(os.path.abspath(config['directories']['results_dir']), campaign_id_no_space,))

    # add temp dir(s) if available
    if tempfile.gettempdir().lower() != os.getcwd().lower():
        # Only add tempdir if it's valid.  Otherwise you get cwd
        dirs.add(tempfile.gettempdir())
    try:
        dirs.add(os.environ['TMP'])
    except KeyError:
        pass

    try:
        dirs.add(os.environ['TEMP'])
    except KeyError:
        pass

    if not options.pretend:
        tries = 0
        done = False
        skipped = []
        while not done:
            skipped = delete_contents_of(dirs, print_via_log=False)
            # if we got here, no exceptions were thrown
            # so we're done
            if skipped:
                if tries < options.retries:
                    # typically exceptions happen because the OS hasn't
                    # caught up with file lock status, so give it a chance
                    # to do so before the next iteration
                    nap_length = SLEEPTIMER * pow(BACKOFF_FACTOR, tries)
                    tries += 1
                    print '%d files skipped, waiting %0.1fs to retry (%d of %d)' % (len(skipped), nap_length, tries, options.retries)
                    time.sleep(nap_length)
                else:
                    print 'Maximum retries (%d) exceeded.' % options.retries
                    done = True
            else:
                done = True

        for (skipped_item, reason) in skipped:
            print "Skipped file %s: %s" % (skipped_item, reason)

    else:
        parser.print_help()
        print
        print 'Would have deleted the contents of:'
        for d in dirs:
            print '... %s' % d

if __name__ == '__main__':
    main()
