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
Created on September 1, 2016

@organization: cert.org
'''
import logging
import tempfile
import os
import sys
import time
import shutil
import urllib
import platform
from distutils import dir_util
from distutils.spawn import find_executable

from subprocess import call, check_output
from __builtin__ import False

from certfuzz.fuzztools.filetools import rm_rf, best_effort_move

logger = logging.getLogger()
logger.setLevel(logging.WARNING)

def copydir(src, dst):
    logger.debug('Copy dir  %s -> %s', src, dst)
    dir_util.copy_tree(src, dst)

def copyfile(src, dst):
    logger.debug('Copy file %s -> %s', src, dst)
    shutil.copy(src, dst)

def main():
    from optparse import OptionParser

    branch = 'develop'
    target_path = '.'
    blacklist = ['configs']

    if not os.path.isdir('certfuzz'):
        target_path = '..'

    certfuzz_dir = os.path.join(target_path, 'certfuzz')

    platform_system = platform.system()
    if platform_system is 'Windows':
        platform_subdir = 'windows'
    else:
        platform_subdir = 'linux'

    hdlr = logging.StreamHandler()
    logger.addHandler(hdlr)

    usage = "usage: %prog [options]"
    parser = OptionParser(usage)
    parser.add_option('-d', '--debug', dest='debug', action='store_true',
                      help='Enable debug messages')
    parser.add_option('-m', '--master', dest='master',
                      action='store_true', help='Use master branch instead of develop')

    (options, args) = parser.parse_args()

    if options.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    if options.master:
        branch = 'master'

    logger.info('Using %s branch' % branch)

    tempdir = git_update(branch=branch)

    logger.debug('Saving original certfuzz directory as certfuzz.bak')
    old_certfuzz = '%s.bak' % certfuzz_dir
    if os.path.isdir(old_certfuzz):
        logger.debug('Removing old certfuzz directory: %s' % old_certfuzz)
        rm_rf(old_certfuzz)
    os.rename(certfuzz_dir, old_certfuzz)

    logger.info('Moving certfuzz directory from git clone...')
    copydir(os.path.join(tempdir, 'src', 'certfuzz'),
            os.path.join(target_path, 'certfuzz'))

    logger.info('Moving %s-specific files from git clone...' % platform_subdir)
    platform_path = os.path.join(tempdir, 'src', platform_subdir)

    # copy platform-specific content
    for f in os.listdir(platform_path):
        if f in blacklist:
            logger.debug('Skipping %s' % f)
            continue
        f_src = os.path.join(platform_path, f)

        f_dst = os.path.join(target_path, f)
        if os.path.isdir(f_src):
            copydir(f_src, f_dst)
        elif os.path.isfile(f_src):
            copyfile(f_src, f_dst)
        else:
            logger.warning("Not sure what to do with %s", f_src)

    if platform_subdir == 'windows':
        # Artifact of prior FOE roots: bff.yaml lives in an "examples"
        # subdirectory on windows
        git_bff_yaml = os.path.join(
            platform_path, 'configs', 'examples', 'bff.yaml')
        bff_yaml_dest = os.path.join(
            target_path, 'configs', 'examples', 'bff.yaml')
    else:
        # Copy bff.yaml as bff.yaml.example
        git_bff_yaml = os.path.join(
            platform_path, 'configs', 'bff.yaml')
        bff_yaml_dest = os.path.join(
            target_path, 'configs', 'bff.yaml.example')
    logger.debug('Copying %s to %s' % (git_bff_yaml, bff_yaml_dest))
    copyfile(git_bff_yaml, bff_yaml_dest)

    logger.debug('Removing %s' % tempdir)
    rm_rf(tempdir)

def git_update(uri='https://github.com/CERTCC-Vulnerability-Analysis/certfuzz.git', branch='develop'):

    use_pygit = True

    try:
        from git import Repo
    except ImportError:
        use_pygit = False

    tempdir = tempfile.mkdtemp()

    if use_pygit:
        # Use python-git to get certfuzz from github
        repo = Repo.clone_from(uri, tempdir, branch=branch)
        headcommit = repo.head.commit
        headversion = headcommit.hexsha
        gitdate = time.strftime(
            "%a, %d %b %Y %H:%M", time.gmtime(headcommit.committed_date))
        logger.info('Cloned certfuzz version %s' % headversion)
        logger.info('Last modified %s' % gitdate)
    elif find_executable('git'):
        # Shell out to git to get certfuzz from github
        ret = call(['git', 'clone', uri, tempdir, '--branch', branch])
        print('ret: %d' % ret)
        headversion = check_output(['git', 'rev-parse', 'HEAD'], cwd=tempdir)
        gitdate = check_output(
            ['git', 'log', '-1', '--pretty=format:%cd'], cwd=tempdir)
        logger.info('Cloned certfuzz version %s' % headversion)
        logger.info('Last modified %s' % gitdate)
    else:
        # Use urllib to get zip
        zip_update(tempdir, branch=branch)

    return tempdir

def zip_update(tempdir, uri='https://github.com/CERTCC-Vulnerability-Analysis/certfuzz/archive/develop.zip', branch='develop'):

    if sys.version_info < (2, 7, 9):
        logger.warning(
            'Your python version (%s) does not check SSL certificates! This update will not be secure.' % sys.version)
        logger.warning(
            'Consider updating your python version to the latest 2.7.x version.')
        time.sleep(10)

    import zipfile

    if branch is 'master':
        uri = uri.replace('develop.zip', '%s.zip' % branch)

    targetzip = os.path.basename(uri)
    targetzippath = os.path.join(tempdir, targetzip)
    logger.debug('Saving %s to %s' % (uri, targetzippath))
    urllib.urlretrieve(uri, targetzippath)
    bffzip = zipfile.ZipFile(targetzippath, 'r')
    bffzip.extractall(tempdir)
    bffzip.close()
    os.remove(targetzippath)
    subdir = 'certfuzz-%s' % branch
    bff_dir = os.path.join(tempdir, subdir)
    for f in os.listdir(bff_dir):
        fullpath = os.path.join(bff_dir, f)
        best_effort_move(fullpath, tempdir)

if __name__ == '__main__':
    main()
