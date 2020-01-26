# Certego Netscaler Threathunter

Following the incidents related to the exploitation of the CVE-2019-19781 we developed this bash2 compatible script in order to facilitate threat hunting operations. 


**Note #1**: *we take no responsibility for the improper use of this script. We recommend using it with caution on critical systems in production.*

**Note #2**: *except for its optional log file, the script does not perform any writing operations, does not need any installation and can also be launched in fileless mode.*

**Requirements**:

1. Netscaler running on FreeBSD OS
2. _nsroot_ or _root_ privileges

## Purposes:

This script aims to:

1. validate patch of CVE-2019-19781
2. enumerate persistences and artifacts related to CVE-2019-19781
3. guide users to change `ns.conf` credentials to avoid future campaigns and to patch quickly
4. spot possible advanced privilege escalation.

## FileBase Execution

```
shell
cd <path/to/uploaded/netscaler_treathunter.sh>
chmod +x netscaler_threathunter.sh
./netscaler_threathunter.sh -a -l 2>/tmp/netscaler_threathunter_errors.log ### at the moment the script does not log errors
```

## FileLess Execution

```
shell
bash
### then run one of the following commands:
curl 'https://raw.githubusercontent.com/certego/incident_response/master/Netscaler/netscaler_threathunter.sh' 2>/dev/null| bash -s -- -a -l 2>netscaler_threathunter_error.log
fetch -qo - 'https://raw.githubusercontent.com/certego/incident_response/master/Netscaler/netscaler_threathunter.sh' 2>/dev/null| bash -s -- -a -l 2>netscaler_threathunter_error.log
wget -qO - 'https://raw.githubusercontent.com/certego/incident_response/master/Netscaler/netscaler_threathunter.sh' 2>/dev/null | bash -s -- -a -l 2>/tmp/netscaler_threathunter_error.log
```