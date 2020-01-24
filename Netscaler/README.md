# Certego Netscaler Threathunter

Following the incidents related to the exploitation of the CVE-2019-19781 we developed this bash2 compatible script in order to facilitate threat hunting operations. 


**Note #1**: *we take no responsibility for the improper use of this script. We recommend using it with caution on critical systems in production.*

**Note #2**: *except for its optional log file, the script does not perform any writing operations, does not need any installation and can also be launched in fileless mode.*

**Requirements**:

1. Netscaler running on FreeBSD OS
2. At least _curl_ or _fetch_ installed
3. _nsroot_ or _root_ privileges


This script aims to enumerate CVE-2019-19781 exploitation and to spot possible advanced privilege escalation.