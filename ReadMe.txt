
      Data Sanitation script


  This script uses python with Regular Expressions to purge any sensitive data from the log files.


Create the following data structure with clean, dirty and matches subdirectories:

data
└── sanitize
    ├── clean
    ├── dirty
    ├── matches
    └── Sanitize.py

To use the script, place any files, whether a zip archive or collection of files within directory structure of your choice under directory:

   /data/sanitize/dirty

Then run a script as such:

   python3 Sanitize.py

It will output cleaned files under /data/clean/timestamp directory, and create a zip archive /data/sanitize/support-archive-timestamp.zip which you can share with support team.

You can also validate list of IP and Hostnames matches under /data/sanitize/matches/timestamp-match.json

Script will do the following:

  It will look for any zip archive's and unpack them in place (/data/sanitize/dirty)

  Create a new directory under /data/sanitize/clean with a date-and-timestamp of now.

  Create the full directory structure of dirty under  /data/sanitize/clean/timestamp without any files

  Then using re.findall script will search for any matches of IP and Hostname regexes. All unique matches (if they don't already exist) are added to dictionaries of matches with a replacement string (host-1 or ipaddr-2).

  These dictionaries will be printed under /data/sanitize/matches/timestamp-match.json for review.

  Each of the dictionary keys (matches) with it's value (replacement string) is then added programatically to REGEXES list.

  Finally in a for loop going through all of the files of dirty one-by-one and line by line it will search for REGEXES and substitute them with text and write them to /data/clean/timestamp directory

  When finished as a last step it will create a zip archive of clean logfiles under /data/sanitize/ called support-archive-timestamp.zip - after you examine log files you can share this file with support.


Regular exressions are the most important part. This script is only as good as REGEX matches are. They are defined together with text we want them replaced with in the REGEXES variable.

List of REGEXES in script is by no means exhaustive.

Currently (v3.0) they include EMAIL address, AWS Internal Hostname. Aditionally IP address and FQDN(Hostname) regexes are searched for and then list of matches is added to REGEXES to replace with unique values.

If you need to update it first of all you have to figure out if we just want to do replacement of matches with the same text, or whether they need to be unique as with Hostnames and IPs.

In case of replacement with the same text, REGEX and replacement string just need to be added to REGEXES list.

In case we need further logic new regex needs to be defined at the top of the script (simmilar to ip_regex and hn_regex).

Keep in mind that these regexes should only use non-capturing groups (?:), as if you use capturing groups, group matches are returned and not the full match.

Dictionary, counter , section with re.findall and section where we append REGEXES list needs to be added under find_matches function.

Patterns like external AWS hostnames, AWS Load Balancer names have been shown in testing to be covered by FQDN regex. Reverse IPs were also covered by IP and FQDN patterns too.

Good places to test REGEX behaviour are: https://regex101.com/ (select Python) and https://pythex.org/

Many regex solutions and patterns for most commonly needed searches can be found on stackoverflow.com , also very helpful Regex library site is: https://regexlib.com/Search.aspx?
