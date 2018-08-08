#!/bin/bash

start_time="$(date +%s)"
uptime="$(uptime)"
freemem="$(free -g)"
freedisk="$(df -h | grep '/'|sort -nr -k5)"
docroots="$(cat /etc/httpd/conf.d/*.conf |grep DocumentRoot | grep -v '#'|awk '{print $2}'|sort |uniq)"
hostname="$(hostname)"
sendmailqueue="$(mailq | tail -n1 | awk '{print $3}')"
postfixmailqueue="$(mailq | tail -n1 | awk '{print $5}')"
webuser="apache"

#Hostname
echo "Hostname: $hostname"
echo

#Uptime
echo "Uptime:"
echo "$uptime"
echo

#Free Memory
echo "Memory Usage (Gigabytes):"
echo "$freemem"
echo

#Disk Space
echo "Disk Space:"
echo "$freedisk"
echo

#Mail Queue
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




#CMS Updates Listing Routine
mkdir -p /opt/scripts/
rm -rf /opt/scripts/scan_results.txt
echo "Docroots found in /etc/httpd/conf.d/*.conf:" >> /opt/scripts/scan_results.txt
echo "$docroots:" >> /opt/scripts/scan_results.txt
echo >> /opt/scripts/scan_results.txt
echo >> /opt/scripts/scan_results.txt

echo "Scanning for oustanding Drupal/Wordpress updates. This can take awhile, please be patient."
echo "Outstanding Drupal/Wordpress updates. If a module/theme/plugin is listed as having an update available, you will need to apply these ASAP, even if the provided module/theme/plugin is not in use:" >> /opt/scripts/scan_results.txt
for docroot in $docroots; do echo ; cd "$docroot" || exit ; pwd ; wp core version  --allow-root 2>/dev/null ; wp plugin list --allow-root 2>/dev/null | grep -i 'available' ; wp theme list --allow-root 2>/dev/null | grep -i 'available' ; drush status 2>/dev/null | grep -i 'Drupal version'; drush up --security-only -n 2>/dev/null | grep -i 'SECURITY UPDATE available' ; done >> /opt/scripts/scan_results.txt

echo "CMS updates scanning complete. Results will be in /opt/scripts/scan_results.txt"


## MALWARE HUNTING AND RELATED BELOW HERE ####


#PHP files in /uploads/ or /files/
echo "Searching for PHP files within /var/www/*/htdocs/wp-content/uploads/ and /var/www/*/htdocs/sites/default/files/ ."
echo "PHP files within /var/www/*/htdocs/wp-content/uploads/ and /var/www/*/htdocs/sites/default/files/ ." >> /opt/scripts/scan_results.txt
echo "These can be malicious and should be reviewed manually and removed if they are indeed non-legit files:" >> /opt/scripts/scan_results.txt
echo >> /opt/scripts/scan_results.txt
find /var/www/*/htdocs/wp-content/uploads/ /var/www/*/htdocs/sites/default/files/ -name "*.php" >> /opt/scripts/scan_results.txt
echo >> /opt/scripts/scan_results.txt
echo >> /opt/scripts/scan_results.txt
echo

# Binaries within /var/www/ 
echo "Searching for Binary files within /var/www/, /var/tmp, and /tmp. This can take awhile, please be patient. " 
echo "Binary files found within /var/www/, /var/tmp, and /tmp . " >> /opt/scripts/scan_results.txt
echo "These can be malicious and should be reviewed manually and removed if they are indeed non-legit files:" >> /opt/scripts/scan_results.txt
echo >> /opt/scripts/scan_results.txt
find /var/www/ /var/tmp/ /tmp/ -type f -exec file -i '{}' \; | grep 'x-executable; charset=binary' >> /opt/scripts/scan_results.txt
echo >> /opt/scripts/scan_results.txt
echo >> /opt/scripts/scan_results.txt
echo

# Files owned apache:apache  within /var/www/ /var/tmp/ /tmp/
# Note: need to update this section to include OS detection (cent and deb) to include the www-data user
# Note: this portion will need filtering added as a pipe to 'grep -v' or blacklisting added to the find command. Until then, expect this to be verbose
echo "Scanning for files and directories owned $webuser:$webuser within /tmp, /var/tmp, and /var/www . " 
echo "Files and directories owned apache:apache within /tmp, /var/tmp, and /var/www:" >> /opt/scripts/scan_results.txt
echo "These are typically malicious." >> /opt/scripts/scan_results.txt
find /tmp/ /var/tmp/ /var/www/ -user $webuser -group $webuser >> /opt/scripts/scan_results.txt
echo >> /opt/scripts/scan_results.txt
echo >> /opt/scripts/scan_results.txt
echo

finish_time="$(date +%s)"

#Send Results Via Mail - commented out for testing
#mail -s 'CMS updates for $hostname' user@hostname.tld < /opt/scripts/updates.txt

echo "Time duration: $((finish_time - start_time)) secs."
