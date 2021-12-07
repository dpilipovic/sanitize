#!/bin/python3

"""
Data Sanitize Python script
Author: Dusan Pilipovic Dusan.Pilipovic@dynatrace.com
v1.0 10-19-2020
v2.0 10-23-2020 - Changed script so that each FQDN that was found is replaced with unique host- parameter
v3.0 10-26-2020 - Modified script to update REGEXES with FQDN amd IP matches so we only replace once
v4.0 12-06-2021 - Added , errors='ignore' to lines 72 and 136 - so that script doesn't fail if it comes across non-UTF8 encoded characters
"""

import os, os.path, shutil, re, fnmatch
from datetime import datetime
import zipfile
import json

# Define paths
base = datetime.now().strftime("%m-%d-%Y-%H-%M-%S")
src = '/data/sanitize/dirty'
copydest = '/data/sanitize/clean/' + base

# Define Regexes - most important part, it's a list of compiled regular expressions with the text we want to replace it with
# They include email addresses, IP's, FQDN Hostnames and an AWS internal hostnames,  external AWS hostnames and Load Balancer names are covered by FQDN
# its much faster if you compile your regexes before you
# actually use them in a loop

REGEXES = [(re.compile(r"(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|'(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*')@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])"), '*** EMAIL REPLACED ***'),
           (re.compile(r"ip(-[0-9]{1,3}){4}"), '*** AWS INT. HOSTNAME REPLACED ***')]

# ip_regex and hn_regex are used to find matches on IP addresses and Hostnames; Then those matches are added to REGEXES list before replacement
# regexes defined in REGEXES variable above just do complete replacement with the same text, ip_regex and hn_regex matches will be replaced with unique values
# as in host A becomes host-1 and host B becomes host-2;
# This was listed as a requirement by Support, as to make support logs easier to debug and that they can figure out which host talks to which.
# Note that both ip_regex and hn_regex are using non-capturing groups (:?) in order to return full matches and not capturing group matches
#
ip_regex = re.compile(r"(?:25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\.(?:25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(?:25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(?:25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])")

hn_regex = re.compile(r"[a-zA-Z0-9\-\.]+\.(?:com|org|net|mil|edu|COM|ORG|NET|MIL|EDU)")

def unpack_zipfiles(src):
    # Look for any zip files in the src dir via fnmatch and os.walk, unpack and remove zip
    print("Unpacking zip files at dirty directory, if any...")
    filePattern = '*.zip'
    for path, dirs, files in os.walk(os.path.abspath(src)):
      for filename in fnmatch.filter(files, filePattern):
        filepath = os.path.join(path, filename)
        zip_ref = zipfile.ZipFile(filepath)
        zip_ref.extractall(src)
        zip_ref.close()
        os.remove(filepath)

def ig_f(dir, files):
    # Get list of files in source to ignore when creating new directory structure
    return [f for f in files if os.path.isfile(os.path.join(dir, f))]

def copy_dir_tree(src, copydest):
    # Create a directory tree without files at destination
    print("Creating new directory structure at clean dir...")
    shutil.copytree(src, copydest, ignore=ig_f)


def find_matches(src, ip_regex, hn_regex, base, REGEXES):
    # Get a list of matches on ip_regex and hn_regex, create unique match dictionaries and then add them to REGEXES for replacement
    # Define dictionaries and counters
    ip_repl_d = {}
    ip_counter = 0
    hn_repl_d = {}
    hn_counter = 0
    srcfiles = [os.path.join(dp, f) for dp, dn, filenames in os.walk(src) for f in filenames]
    print("Searching for IP address and Hostname patterns in files and adding them to dictionary. This might take a while ...")
    for file in srcfiles:
      with open(file, 'r', errors='ignore') as f:
        for line in f:

          # Search for ip_regex matches and add unique match values to ip_repl_d dictionary
          if re.findall(ip_regex, line):
            ip_results = re.findall(ip_regex, line)
            ip_key = ip_results[0]
            if ip_key not in ip_repl_d:
              ip_counter = ip_counter + 1
              ip_val = ('ipaddr-' + str(ip_counter))
              ip_repl_d[ip_key] = ip_val

          # Search for hn_regex matches and add unique match values to hn_repl_d dictionary
          elif re.findall(hn_regex, line):
            hn_results = re.findall(hn_regex, line)
            hn_key = hn_results[0]
            if hn_key not in hn_repl_d:
              hn_counter = hn_counter + 1
              hn_val = ('host-' + str(hn_counter))
              hn_repl_d[hn_key] = hn_val


    # Let's capture replacement dictionaries of IPs and Hostnames for our own validation
    # It's a bit more readable in json format
    matches = '/data/sanitize/matches/match-' + base + '.json'
    print('Replacement dictionary of IP/Hostname matches is saved here: {}'.format(matches))
    ip_json = json.dumps(ip_repl_d)
    hn_json = json.dumps(hn_repl_d)
    m_file = open(matches,"w")
    m_file.write( '# IP replacement dictionary: ')
    m_file.write('\n')
    m_file.write( ip_json )
    m_file.write('\n')
    m_file.write( '# Hostname replacement dictionary: ')
    m_file.write('\n')
    m_file.write( hn_json )
    m_file.close()

    # Now append these matches to REGEXES list
    print("Adding IP and Hostname matches to REGEXES list for replacement...")
    for key, value in ip_repl_d.items():
      search = (re.compile(key))
      replace = value
      REGEXES.append((search, replace))

    for key, value in hn_repl_d.items():
      search = (re.compile(key))
      replace = value
      REGEXES.append((search, replace))

    #print(REGEXES)
    return REGEXES

def sanitize_files(src, copydest, REGEXES):
    # First obtain a list of files in src dir, then substitute any REGEXES it finds in all files!
    myfiles = [os.path.join(dp, f) for dp, dn, filenames in os.walk(src) for f in filenames]

    print("Now doing a replacement of all matches. This might take a while ...")
    for f in myfiles:
        input_file = f
        output_file = f.replace(src, copydest, 1)
        print('Original file: {}'.format(input_file))
        print('Cleaned file: {}'.format(output_file))

        with open(input_file, "r", errors='ignore') as fi, open(output_file, "w") as fo:
            for line in fi:
                for search, replace in REGEXES:
                    line = search.sub(replace, line)
                fo.write(line)
        # both the input and output files are closed automatically
        # after the with statement closes

def create_result_archive(base, copydest):
    output_filename = 'support-archive-' + base
    shutil.make_archive(output_filename, 'zip', copydest)
    print('Created Archive of cleaned files : {}.zip'.format(output_filename))

def main():
    unpack_zipfiles(src)
    copy_dir_tree(src, copydest)
    find_matches(src, ip_regex, hn_regex, base, REGEXES)
    sanitize_files(src, copydest, REGEXES)
    create_result_archive(base, copydest)

if __name__ == "__main__":
    main()
