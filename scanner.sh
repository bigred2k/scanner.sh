#!/bin/bash

start_time="$(date +%s)"
uptime="$(uptime)"
freemem="$(free -g)"
freedisk="$(df -h | grep '/'|sort -nr -k5)"
docroots="$(cat /etc/httpd/conf.d/*.conf |grep DocumentRoot | grep -v '#'|awk '{print $2}'|sort |uniq)"
hostname="$(hostname)"
sendmailqueue="$(mailq | tail -n1 | awk '{print $3}')"
postfixmailqueue="$(mailq | tail -n1 | awk '{print $5}')"
webuser="unknown"
arch="$(head -n1 /etc/issue)"
maldethits="$(maldet -l | grep '\-\-report' | tail -n1 |awk '{print $NF}')"

if [[ "$arch" == *"CentOS"* ]] || [[ "$arch" == *"\S"* ]]; then
   webuser="apache"
elif [[ "$arch" == *"Ubuntu"* ]]; then
   webuser="www-data"
fi

# Hostname
echo "Hostname: $hostname"
echo

# Uptime
echo "Uptime:"
echo "$uptime"
echo

# Free Memory
echo "Memory Usage (Gigabytes):"
echo "$freemem"
echo

# Disk Space
echo "Disk Space:"
echo "$freedisk"
echo

# Mail Queue
if pgrep -x "master" > /dev/null;
then
    echo "Postfix Queue: $postfixmailqueue"
elif pgrep -x "sendmail" > /dev/null;
then
    echo "Sendmail Queue: $sendmailqueue"
else
    echo "Unknown Mail System"
fi
echo
echo


# Clean up from last run
if [ ! -d "/opt/scripts/" ]; then
  mkdir -p /opt/scripts/
fi

if [ -f "/opt/scripts/scan_results.txt" ]; then
  rm -rf /opt/scripts/scan_results.txt
fi

# Maldet scan
echo "Scanning with maldet. This could take awhile."
maldet -u
freshclam
maldet -a /
echo "Maldet scan complete"

# Maldet results from last scan
echo "Getting Maldet results from last scan and adding to /opt/scripts/scan_results.txt"
echo "During a routine scan of your server, $hostname, we detected one or more suspicious files indicating the presence of malware on your server. Most often these are a result of an out of date or unpatched CMS, or unpatched plugins or themes.

Due to security concerns, we ask that your team address this issue as soon as possible. In the event that we don't hear back that you have addressed the problematic files within the next 24 hours, we must quarantine them.

If we do quarantine the files, there is a possibility that the functionality of your site(s) will be affected.

Please note that it is not sufficient to simply restore from a recent backup, as it is likely that the recent backup would have these files as well.

The list of files our malware scanner found:" >> /opt/scripts/scan_results.txt
echo >> /opt/scripts/scan_results.txt
find /usr/local/maldetect/sess/ -name session.hits.$maldethits -exec cat {} \; >> /opt/scripts/scan_results.txt
echo >> /opt/scripts/scan_results.txt
echo >> /opt/scripts/scan_results.txt
echo "Complete"
echo



#CMS Updates Listing Routine
echo "Step 1 of 5"
echo "Enumerating docroots"
echo "Docroots found in /etc/httpd/conf.d/*.conf:"
echo "$docroots"
echo "Docroot enumeration complete"
echo

echo "Step 2 of 5"
echo "Scanning for oustanding Drupal/Wordpress updates. This can take awhile, please be patient."
echo "Here is a list of outstanding Drupal/Wordpress updates. If a module/theme/plugin is listed as having an update available, you will need to apply these ASAP, even if the provided module/theme/plugin is not in use:" >> /opt/scripts/scan_results.txt
for docroot in $docroots; do echo ; cd "$docroot" || exit ; pwd ; wp core version  --allow-root 2>/dev/null ; wp plugin list --allow-root 2>/dev/null | grep -i 'available' ; wp theme list --allow-root 2>/dev/null | grep -i 'available' ; drush status 2>/dev/null | grep -i 'Drupal version'; drush up --security-only -n 2>/dev/null | grep -i 'SECURITY UPDATE available' ; done >> /opt/scripts/scan_results.txt
echo "CMS updates scanning complete."
echo

## MALWARE HUNTING AND RELATED BELOW HERE ####


echo "Additionally, we found the following suspicious files that may have not been detected by our malware scanning software. Please note that this secondary list is likely to contain false-positives, but should still be investigated:" >> /opt/scripts/scan_results.txt
echo >> /opt/scripts/scan_results.txt

#PHP files in /uploads/ or /files/
echo "Step 3 of 5"
echo "Searching for PHP files within /var/www/*/htdocs/wp-content/uploads/ and /var/www/*/htdocs/sites/default/files/ ."
echo "PHP files within /var/www/*/htdocs/wp-content/uploads/ and /var/www/*/htdocs/sites/default/files/ ." >> /opt/scripts/scan_results.txt
echo "These can be malicious and should be reviewed manually and removed if they are indeed non-legit files:" >> /opt/scripts/scan_results.txt
echo >> /opt/scripts/scan_results.txt
find /var/www/*/htdocs/wp-content/uploads/ /var/www/*/htdocs/sites/default/files/ -name "*.php" >> /opt/scripts/scan_results.txt
echo >> /opt/scripts/scan_results.txt
echo >> /opt/scripts/scan_results.txt
echo "PHP file scan complete"
echo

# Binaries within /var/www/ /var/tmp/ /var/lib/dav/ /tmp/ and /dev/shm/
echo "Step 4 of 5"
echo "Searching for Binary files within /dev/shm, /var/tmp, /var/lib/dav, and /var/www/ . This can take awhile, please be patient. " 
echo "Binary files found within /dev/shm/, /var/tmp, /var/lib/dav, /tmp and /var/www/ . " >> /opt/scripts/scan_results.txt
echo "These can be malicious and should be reviewed manually and removed if they are indeed non-legit files:" >> /opt/scripts/scan_results.txt
echo >> /opt/scripts/scan_results.txt
find /dev/shm/ /var/tmp/ /var/lib/dav/ /tmp/ /var/www/ -type f -exec file -i '{}' \; | grep 'x-executable; charset=binary' >> /opt/scripts/scan_results.txt
echo >> /opt/scripts/scan_results.txt
echo >> /opt/scripts/scan_results.txt
echo "Binary file scan complete"
echo

# Files owned apache:apache  within /var/www/ /var/tmp/ /var/lib/dav/ /tmp/ /dev/shm/
# Note: need to update this section to include OS detection (cent and deb) to include the www-data user
# Note: this portion will need filtering added as a pipe to 'grep -v' or blacklisting added to the find command. Until then, expect this to be verbose
echo "Step 5 of 5"
echo "Scanning for files and directories owned $webuser:$webuser within /tmp, /var/tmp, /var/www and /dev/shm/. " 
echo "Files and directories owned apache:apache within /tmp, /var/tmp, /var/lib/dav, /var/www and /dev/shm:" >> /opt/scripts/scan_results.txt
echo "These can be malicious and should be reviewed manually and removed if they are indeed non-legit files:" >> /opt/scripts/scan_results.txt
find /tmp/ /var/tmp/ /dev/shm/ /var/lib/dav/ /var/www/ -user $webuser -group $webuser | grep -v '.css\|.js' >> /opt/scripts/scan_results.txt
echo >> /opt/scripts/scan_results.txt
echo >> /opt/scripts/scan_results.txt
echo "Scan complete. Results are in /opt/scripts/scan_results.txt"
echo

finish_time="$(date +%s)"

#Send Results Via Mail - commented out for testing
#mail -s 'CMS updates for $hostname' user@hostname.tld < /opt/scripts/updates.txt

echo "Time duration: $((finish_time - start_time)) secs."
