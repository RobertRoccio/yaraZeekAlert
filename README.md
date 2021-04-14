# yaraZeekAlert
This script scans the files extracted by Zeek with YARA rules located on the rules folder on a Linux based Zeek sensor, if there is a match it sends email alerts to the email address specified in the mailTo parameter on yaraAlert.conf file. The alert includes network context of the file transfer and attaches the suspicious file if it is less than 10 MB. Alerted files are copied locally to the alerted files folder.

# Installation
-Prerequisites: 
sudo apt-get install yara, cron, 7za, sed,
install zeek per official documentation

Clone the repository
create yaraAlert.conf or rename yaraAlert_template.conf
fill in the relevant values for the administrator email address, password, server, and port
 sudo ./setup.sh

 sudo zeekctl deploy



