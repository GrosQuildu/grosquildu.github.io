#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
~Gros
'''

from glob import glob
from os import path
from os import listdir, mkdir
from shutil import copyfile
from sys import exit
import json
import subprocess
from getpass import getpass
try:
    from shlex import quote
except:
    from pipes import quote


master_passphrase = getpass('Master passphrase: ')

WORK_DIR = '/home/gros/Informatics/hax/blog/blog/'
FLAGS = path.join(WORK_DIR, 'assets/pwnablekr/plain/flags.json')
CUT_STRING = '(--CUT-HERE--)'

ENC_CMD = "tar -C {indir} -Pcz {infile} | gpg --symmetric --batch --yes --passphrase {passphrase} -o {outfile}"

asssets_dir = path.join(WORK_DIR, 'assets/pwnablekr/')
plain_dir = path.join(asssets_dir, 'plain/')
ciphered_dir = path.join(asssets_dir, 'cipher/')
posts_dir = path.join(WORK_DIR, '_pwnablekr')


# check flags
if not path.isfile(FLAGS):
    print('No flags file')
    exit(1)

with open(FLAGS, 'rb') as f:
    flags = json.load(f)

# check basic dirs
if not path.isdir(ciphered_dir):
    mkdir(ciphered_dir)

if not path.isdir(posts_dir):
    mkdir(posts_dir)

# parse plain directory
for one_category in listdir(plain_dir):
    # ---- CATEGORY
    if not path.isdir(path.join(plain_dir, one_category)):
        continue
    print('Parsing {}'.format(one_category))

    if not path.isdir(path.join(ciphered_dir, one_category)):
        mkdir(path.join(ciphered_dir, one_category))

    if not path.isdir(path.join(posts_dir, one_category)):
        mkdir(path.join(posts_dir, one_category))

    # ---- TASK
    for one_task in listdir(path.join(plain_dir, one_category)):
        if one_task not in flags:
            print('\t - {} not in flags'.format(one_task))
            continue

        one_task_plain_dir = path.join(plain_dir, one_category, one_task)
        one_task_enc_dir = path.join(ciphered_dir, one_category, one_task)

        if not path.isdir(one_task_plain_dir):
            continue
        print('\t - parsing {}'.format(one_task))

        if not path.isdir(one_task_enc_dir):
            mkdir(one_task_enc_dir)

        for one_task_file in listdir(one_task_plain_dir):
            one_task_file_plain = path.join(one_task_plain_dir, one_task_file)
            one_task_file_enc = path.join(one_task_enc_dir, one_task_file)

            if one_task_file.endswith('.md'):
                # cut and copy .md file to dir for encryption and _posts
                with open(one_task_file_plain, 'rb') as f:
                    plain_file = f.read()

                if CUT_STRING in plain_file:
                    plain_file = plain_file[:plain_file.index(CUT_STRING)]
                else:
                    print('\t\t - no cut string!')

                with open(one_task_file_enc, 'wb') as f:
                    f.write(plain_file)

                # copy to _posts
                with open(path.join(posts_dir, one_category, one_task_file), 'wb') as f:
                    f.write(plain_file)
            else:
                # copy file to dir for encryption
                copyfile(
                    one_task_file_plain,
                    one_task_file_enc
                )

        # create encrypted tar
        # rm redundant dir
        enc_cmd = ENC_CMD.format(indir=quote(path.join(plain_dir, one_category)),
                                    infile=quote(one_task),
                                    outfile=quote(one_task_enc_dir + '.tar.gz.gpg'),
                                    passphrase=quote(flags[one_task]))
        try:
            subprocess.call(enc_cmd, shell=True)
        except Exception as e:
            print(one_task, e)

        rm_cd = 'rm -r {infile}'.format(infile=quote(one_task_enc_dir))
        try:
            subprocess.call(rm_cd, shell=True)
        except Exception as e:
            print(one_task, e)

# master encrypted tar (all stuff)
print('Generating master tar')
enc_cmd = ENC_CMD.format(indir=quote(asssets_dir),
                            infile=quote('plain'),
                            outfile=quote(path.join(asssets_dir, 'all_tasks.tar.gz.gpg')),
                            passphrase=quote(master_passphrase))
try:
    subprocess.call(enc_cmd, shell=True)
except Exception as e:
    print(one_task, e)