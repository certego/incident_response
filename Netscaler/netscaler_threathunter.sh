#!/usr/bin/env bash

### Following the incidents related to the exploitation of the CVE-2019-19781 we developed this bash2 compatible script in order to facilitate threat hunting operations.
### This is bash2 compatible script aims to enumerate CVE-2019-19781 exploitation and to spot possible advanced privilege escalation
#
# Note1: we take no responsibility for the improper use of this script. We recommend using it with caution on critical systems in production.
# Note2: except for its optional log file, the script does not perform any writing operations, does not need any installation and can also be launched in fileless mode.
#
# Author: @gabriele_pippi from @certego_irt
# License: AGPL-3.0
#
## links:
#   https://www.certego.net/en/news/netscaler-threathunter-sh-a-bash2-compatible-script-to-digital-forensic-and-incident-response-on-citrix-adc/
#   https://github.com/certego/incident_response/blob/master/Netscaler/README.md
#   https://twitter.com/gabriele_pippi
#   https://twitter.com/certego_irt
#
## some references:
#   https://twitter.com/cyb3rops/status/1216008398073778176 @cyb3rops
#   https://www.reddit.com/r/blueteamsec/comments/en4m7j/multiple_exploits_for_cve201919781_citrix/
#   https://fox-it.com/nl/actueel/media/fox-it-citrix-advisory-update/
#
### Requirements for an effective execution:
#
#   - Netscaler running on FreeBSD OS
#   - at least curl or fetch installed
#   - nsroot/root privileges
#
### To execute this script without writing file to disk:
#    curl 'https://raw.githubusercontent.com/certego/incident_response/master/Netscaler/netscaler_threathunter.sh' 2>/dev/null| bash -s -- -a -l 2>/tmp/netscaler_threathunter_error.log
#    fetch -qo - 'https://raw.githubusercontent.com/certego/incident_response/master/Netscaler/netscaler_threathunter.sh' 2>/dev/null| bash -s -- -a -l 2>/tmp/netscaler_threathunter_error.log
#    wget -qO - 'https://raw.githubusercontent.com/certego/incident_response/master/Netscaler/netscaler_threathunter.sh' 2>/dev/null | bash -s -- -a -l 2>/tmp/netscaler_threathunter_error.log

CURRENT_SHELL="$(ps -p `ps -o ppid= $$` -o command | tail -1)"

FILELESS_CURRENT_SHELL="$(ps -p $$ -o command | tail -1)"

if [ "`echo "$CURRENT_SHELL" | grep -sE '(^|/)bash(\ |$)'`" ]
    then IS_BASH=1
elif [ "`echo "$FILELESS_CURRENT_SHELL" | grep -sE '(^|/)bash(\ |$)'`" ]
    then IS_BASH=1
elif [ "`echo "$CURRENT_SHELL" | grep -sE '(^|/)(sh|-sh\ \(sh\))(\ |$)'`" ]
    then IS_SH=1
        echo "[!] BSD sh is not correctly supported"
        echo "[!] Please run this script with bash, current shell: $CURRENT_SHELL"
        exit
else
    echo "[!] Please run this script with bash, current shell: $CURRENT_SHELL"
    exit
fi

colored_print(){
    echo -e "\e[00;$1m$2\e[00m"
}

help()
    {

        colored_print 34 '╔═╗┌─┐┬─┐┌┬┐┌─┐┌─┐┌─┐'                     
        colored_print 34 '║  ├┤ ├┬┘ │ ├┤ │ ┬│ │'                    
        colored_print 34 '╚═╝└─┘┴└─ ┴ └─┘└─┘└─┘'                     
        colored_print 34 '╔╗╔┌─┐┌┬┐┌─┐┌─┐┌─┐┬  ┌─┐┬─┐'               
        colored_print 34 '║║║├┤  │ └─┐│  ├─┤│  ├┤ ├┬┘'              
        colored_print 34 '╝╚╝└─┘ ┴ └─┘└─┘┴ ┴┴─┘└─┘┴└─'               
        colored_print 34 '      ╔╦╗┬ ┬┬─┐┌─┐┌─┐┌┬┐╦ ╦┬ ┬┌┐┌┌┬┐┌─┐┬─┐'
        colored_print 34 '       ║ ├─┤├┬┘├┤ ├─┤ │ ╠═╣│ ││││ │ ├┤ ├┬┘'
        colored_print 34 '       ╩ ┴ ┴┴└─└─┘┴ ┴ ┴ ╩ ╩└─┘┘└┘ ┴ └─┘┴└─'
        colored_print 34 'Version: 1.0'

        read -r -d "" HELP <<"EOF"

        ### This is bash2 compatible script aims to enumerate CVE-2019-19781 exploitation and to spot possible advanced privilege escalation
        #
        # Note1: we take no responsibility for the improper use of this script. We recommend using it with caution on critical systems in production.
        # Note2: except for its optional log file, the script does not perform any writing operations, does not need any installation and can also be launched in fileless mode.
        #
        ### Requirements for an effective execution:
        #
        #   - Netscaler running on FreeBSD OS
        #   - at least curl or fetch installed
        #   - nsroot/root privileges
        #
        # Author: @gabriele_pippi from @certego_irt
        # License: AGPL-3.0

        [-] Help:



               -t<timestamp>    # specify mintimestamp # example: -t2020-01-09
               -T<timestamp>    # specify maxtimestamp, actually working only on all_users_recent_files and all_nobody_recent_files # example: -T2020-01-09
               -f               # try to run the script on non freebsd system
               -l               # enable logging
               -n               # check nobody based persistences and IOC
               -a               # check all users and root based persistences and IOC
               -C               # get context: add lsof/sockstat, psauxd to output and all users recent files
                                    # this parameter should be used with a reasonably close timestamp otherwise the output could be extremely verbose
        
        [*] To execute this script without writing script to disk:

                curl 'https://raw.githubusercontent.com/certego/incident_response/master/Netscaler/netscaler_threathunter.sh' 2>/dev/null| bash -s -- -a -l 2>/tmp/netscaler_threathunter_error.log
                fetch -qo - 'https://raw.githubusercontent.com/certego/incident_response/master/Netscaler/netscaler_threathunter.sh' 2>/dev/null| bash -s -- -a -l 2>/tmp/netscaler_threathunter_error.log
                wget -qO - 'https://raw.githubusercontent.com/certego/incident_response/master/Netscaler/netscaler_threathunter.sh' 2>/dev/null | bash -s -- -a -l 2>/tmp/netscaler_threathunter_error.log
EOF
        colored_print 34 "$HELP"
                                                

    }

unset mtimestamp Mtimestamp force logging all nobody

while getopts 't:T:flahnC' option
    do
        case "${option}" in
            t) mtimestamp=${OPTARG};;
            T) Mtimestamp=${OPTARG};;
            n) nobody=1;;
            f) force=1;;
            l) logging=1;;
            a) all=1;;
            C) context=1;;
            h) help; exit;;
            *) help; exit;;
        esac
done

if [[ $# == 0 ]]
    then
        help
        exit 1
fi

# even through root permissions it's really difficult to spoof ctime without changing system's date
# therefore ctime was used to control the creation of files that should not be present
# reference: https://unix.stackexchange.com/questions/36021/how-can-i-change-change-date-of-file

if [ $logging ]
    then
        LOG_FILE=/tmp/netscaler_threathunter"-"`date +"%d-%m-%y-%H_%M_%S"`.log
        echo "[*] Start logging to ${LOG_FILE}"
        echo -e "[*] Start logging $(date +"%Y-%m-%d-%H:%M:%S")\n" >> $LOG_FILE ### date -Iseconds not working on FreeBSD
fi

out-string()
    {
        echo "$1"

        if [ $logging ]
            then
                echo "$1" >> $LOG_FILE
        fi
    }


if [ -z $mtimestamp ]
    then
        MINTIMESTAMP="2020-01-09"
else
        date -f "%Y-%m-%d" -j "$mtimestamp" >/dev/null 2>&1
        if [[ $? != 0 ]]
            then
                out-string '[!] Error: Bad mintimestamp, please follow this format: <year>-<month>-<day>'
                exit 1
        fi
        MINTIMESTAMP="$mtimestamp"
fi

if [ -z $Mtimestamp ]
    then
        MAXTIMESTAMP="`date +"%Y-%m-%d"`"
else
        date -f "%Y-%m-%d" -j "$Mtimestamp" >/dev/null 2>&1
        if [[ $? != 0 ]]
            then
                out-string '[!] Error: Bad maxtimestamp, please follow this format: <year>-<month>-<day>'
                exit 1
        fi
        MAXTIMESTAMP="$Mtimestamp"
fi

if [[ $EUID -ne 0 ]]
    then
    echo "[-] Warning: it is recommended to run the script with nsroot/root privileges" 
fi

### FreeBSD appears to natively support birthtime


#debuglog ()
##{
#    if [ $debug ]
#        then
#            if [ $IS_BASH ]
#                then echo -e "\e[00;$1m\n$(date +"%Y-%m-%d-%H:%M:%S") $2 $3" >> $LOG_FILE
#            elif [ $IS_SH ]
#                #then echo "\e[00;$1m\n$(date +"%Y-%m-%d-%H:%M:%S") $2 $3\e[00m"
#                # tested FreeBSD's sh seems to works with -e
#                # I leave the code for any future incompatibilities
#                then echo -e "\e[00;$1m\n$(date +"%Y-%m-%d-%H:%M:%S") $2 $3\e[00m" >> $LOG_FILE
#            else
#                echo -e "\n$(date +"%Y-%m-%d-%H:%M:%S") $2 $3" | tee >> $LOG_FILE
#            fi
#    fi
##}


#info () { debuglog 29 INFO "$1"; }
#warn () { debuglog 33 WARNING "$1"; }
#error () { debuglog 31 ERROR "$1"; }
                                                          
threat_seeker()

{   
    KERNEL_VERSION="`uname -mrs`"

    if [[ "`echo "$KERNEL_VERSION"| grep -svE 'FreeBSD'`" ]]
        then
            if [ ! $force ]
                then
                    out-string "[!] Error: This script is tested only on FreeBSD versions, run this script with force to try on this OS"
                    out-string "    Kernel Version: $KERNEL_VERSION"
                    exit 1
            fi
    fi


    read -r -d '' getoutbound <<"EOF"
    sockstat -c | \
    grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5}$' | \
    grep -Ev '\ (127\.|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.)[0-9.]+:[0-9]{1,5}$'
EOF
    read -r -d '' getlisten <<"EOF"
    sockstat -l | \
    awk -F" " ' $(NF-1) ~ ":[0-9]+$" && $(NF-1) !~ "^(127\.|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.)" {print $0}'
EOF

    read -r -d '' getsmbconf <<"EOF"
    ( curl 'http://127.0.0.1/vpn/../vpns/cfg/smb.conf' --path-as-is --connect-timeout 1 || \
      curl 'https://127.0.0.1/vpn/../vpns/cfg/smb.conf' -k --path-as-is --connect-timeout 1 || \
      fetch --no-verify-peer -T1 -qo - 'http://127.0.0.1/vpn/../vpns/cfg/smb.conf' || \
      fetch --no-verify-peer -T1 -qo - 'https://127.0.0.1/vpn/../vpns/cfg/smb.conf' ) 2>/dev/null | \
      grep -sE "encrypt\ passwords"
EOF

    read -r -d '' checkawsmetadata <<"EOF"
    ( curl 'http://169.254.169.254/latest/meta-data/instance-id' --connect-timeout 1 || \
      fetch --no-verify-peer -T1 -qo - 'http://169.254.169.254/latest/meta-data/instance-id' ) 2>/dev/null
EOF

### possible regex bypass to upgrade with \( -path -o -path \) -prune -o
    read -r -d '' unknown_writable_root_file_find <<"EOF"
    find / ! \( -regex '^/dev/.*' -o -regex '^/proc/.*' -o -regex '^/var/netscaler/help.*' \
    -o -regex '^/var/netscaler/gui/admin_ui/nitro_client.*' -o -regex '^/var/netscaler/nsbackup.*' -o -regex '^/var/netscaler/gslb.*' \
    -o -regex '^/flash/.*' \) -user root -perm -o=w -ls 2>/dev/null
EOF

    read -r -d '' all_nobody_recents_files_find <<"EOF"
    find / \( -path /dev -o -path /proc \) -prune -o -user nobody \
 -type f -a \( -newerct MINTIMESTAMP -o -newermt MINTIMESTAMP \) -a \( ! -newerct MAXTIMESTAMP -o ! -newermt MAXTIMESTAMP \) -ls 2>/dev/null
EOF

all_nobody_recents_files_find="`echo "$all_nobody_recents_files_find" | sed -r "s/MINTIMESTAMP/$MINTIMESTAMP/g"`"
all_nobody_recents_files_find="`echo "$all_nobody_recents_files_find" | sed -r "s/MAXTIMESTAMP/$MAXTIMESTAMP/g"`"

    read -r -d '' all_users_recents_files_find <<"EOF"
    find / \( -path /dev -o -path /proc \) \
    -prune -o \( -newerct MINTIMESTAMP -o -newermt MINTIMESTAMP \) -a \( ! -newerct MAXTIMESTAMP -o ! -newermt MAXTIMESTAMP \) -ls 2>/dev/null
EOF


all_users_recents_files_find="`echo "$all_users_recents_files_find" | sed -r "s/MINTIMESTAMP/$MINTIMESTAMP/g"`"
all_users_recents_files_find="`echo "$all_users_recents_files_find" | sed -r "s/MAXTIMESTAMP/$MAXTIMESTAMP/g"`"





    SUID_SGID_REGEX="^(/netscaler/ping|\
/netscaler/ping6|\
/netscaler/traceroute|\
/netscaler/traceroute6|\
/sbin/mksnap_ffs|\
/sbin/shutdown|\
/sbin/poweroff|\
/usr/bin/fstat|\
/usr/bin/lock|\
/usr/bin/login|\
/usr/bin/netstat|\
/usr/bin/passwd|\
/usr/bin/yppasswd|\
/usr/bin/su|\
/usr/bin/wall|\
/usr/bin/write|\
/usr/bin/crontab|\
/usr/libexec/ssh-keysign|\
/var/nslog/nslog\.nextfile|\
/var/run/nsprofmgmt\.pid|\
/var/configd_devno)$"

    nobody_seeker()

        {   ### this function tries to detect exploitation of CVE-2019-19781 (Citrix ADC/Netscaler)
            

            ### some OS found with bash version 2 ;)
            #
            #declare -A TRUSTED_SERVICES=( \
            #    [22]="/usr/sbin/sshd" \
            #    [80]="/bin/httpd" \
            #    [123]="/usr/sbin/ntpd" \
            #    [443]="/bin/httpd" \
            #    [3010]="/netscaler/nsconfigd" \
            #    [4001]="/netscaler/imi" \
            #    [4050]="/netscaler/nscopo" \
            #)
            #
            #thanks to stackoverflow community for support https://stackoverflow.com/questions/1494178/how-to-define-hash-tables-in-bash
            #

            ### dirty hashtable for bash2
            trusted_services_hashtable()
                {
                    ### it may also be worth checking all the md5 hashes

                    ARRAY=( 
                        '22="/usr/sbin/sshd"'
                        '80="/bin/httpd"'
                        '123="/usr/sbin/ntpd"'
                        '443="/bin/httpd"'
                        '3010="/netscaler/nsconfigd"'
                        '4001="/netscaler/imi"'
                        '4050="/netscaler/nscopo"'
                        )
                    if [[ "$1" == "fetch" ]]
                        then
                            for entry in "${ARRAY[@]}" ; do
                                KEY="${entry%%=*}"
                                VALUE="${entry##*=}"
                                if [ "`echo "$KEY" | grep -sE "^$2$"`" ]
                                    then
                                        printf "%s" "$VALUE"
                                fi
                            done
                    fi

                    if [[ "$1" == "keys" ]]
                        then
                            for entry in "${ARRAY[@]}" ; do
                                KEY="${entry%%=*}"
                                printf "%s " "$KEY"
                            done
                    fi
                }

            get_unknown_services()
                {
                    S_LISTEN_DAEMONS=`bash -c "$getlisten"`
                    unknown_services_counter=0

                    while read S_LISTEN_DAEMON
                        do
                            PORT=`echo "$S_LISTEN_DAEMON" | awk -F' ' '{print $(NF-1)}' | awk -F: '{print $NF}'`

                            if [[ `echo "$( trusted_services_hashtable keys )" | grep -sE "(^|\ )${PORT}(\ |$)"` ]]
                                then
                                    REGEX=":$PORT$"
                                    PIDS_LIST=`echo "$S_LISTEN_DAEMONS" | awk -vregex="$REGEX" -F' ' '$(NF-1) ~ regex {print $3}'`
                                    if [ -z "$PIDS_LIST" ] ; then continue ; fi
                                    for PID in $PIDS_LIST
                                        do
                                            BINARY_PATH="$( ps -p $PID -o command | tail -1 | awk -F' ' '{print $1}')"
                                            
                                            if [[ "\"$BINARY_PATH\"" == "$( trusted_services_hashtable fetch $PORT )" ]]
                                                then continue
                                            else
                                                unknown_services_counter=$(( $unknown_services_counter + 1 ))
                                                if [[ $unknown_services_counter == 1 ]]
                                                    then
                                                        out-string    "################################# [Unknown daemons] #################################"
                                                fi

                                                out-string "[!] Unknown service ${BINARY_PATH} is binding trusted netscaler port ${PORT}:"
                                                out-string "${S_LISTEN_DAEMON}"
                                            fi
                                    done
                            else

                                unknown_services_counter=$(( $unknown_services_counter + 1 ))
                                if [[ $unknown_services_counter == 1 ]]
                                then
                                    out-string    "################################ [Unknown Services] #################################"
                                fi
                                out-string "$S_LISTEN_DAEMON"
                            fi
                        done <<<"$(echo "$S_LISTEN_DAEMONS")"

                            #< <(echo "$S_LISTEN_DAEMONS") # bash: /dev/fd/62: No such file or directory # https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=188699

                    
                    if [ $unknown_services_counter  -ge 1 ]
                        then
                            out-string    "#####################################################################################"
                    fi
                }

            get_outbound_connections()

                {
                    S_OUTBOUND_CONNECTIONS="`bash -c "$getoutbound"`"
                    if [[ ! -z "$S_OUTBOUND_CONNECTIONS" ]]
                        then
                            out-string    "################################ [OUTBOUND TRAFFIC] #################################"
                            out-string "$S_OUTBOUND_CONNECTIONS"
                            out-string    "#####################################################################################"
                    fi
                    
                }
            
            check_aws_default_credentials()

                {
                    AWS_DEFAULT_METADATA_FILE="/flash/nsconfig/.AWS/instance-id"
                    AWS_DEFAULT_METADATA_REQUEST="`bash -c "$checkawsmetadata"`"

                    if [[ -e "$AWS_DEFAULT_METADATA_FILE" || ! -z $AWS_DEFAULT_METADATA_REQUEST ]]
                        then
                            out-string    "############################# [AWS default credentials] #############################"
                            if [[ -e "$AWS_DEFAULT_METADATA_FILE" ]]
                                then
                                    out-string    "[!] Possible AWS default credentials file found here: $AWS_DEFAULT_METADATA_FILE"
                                    out-string    "[*] Content:"
                                    out-string    "`cat $AWS_DEFAULT_METADATA_FILE`"
                                    out-string    ""
                            fi
                            if [[ ! -z "$AWS_DEFAULT_METADATA_REQUEST" ]]
                                then
                                    out-string    "[!] Possible AWS default credentials found here http://169.254.169.254/latest/meta-data/instance-id"
                                    out-string    "[*] Response:"
                                    out-string    "`$AWS_DEFAULT_METADATA_REQUEST`"
                            fi
                            out-string    "[*] Details: https://twitter.com/KevTheHermit/status/1216318333219491840"

                            AWS_DEFAULT_METADATA_FILE_ATIME="`find /flash/nsconfig/.AWS/instance-id -type f -newerat $MINTIMESTAMP 2>/dev/null`"

                            if [[ ! -z "$AWS_DEFAULT_METADATA_FILE_ATIME" ]]
                                then out-string "[!!!] AWS default credentials file was accessed withing the atime $MINTIMESTAMP"
                            fi
                            out-string    "#####################################################################################"
                    fi
                }

            check_cve()

                {

                    SMB_CONF_OUT=`bash -c "$getsmbconf"`
                    if [ ! -z "$SMB_CONF_OUT" ]
                        then
                            out-string    "################################# [CVE-2019-19781] ##################################"
                            out-string    "[!] The host is vulnerable to CVE-2019-19781"
                            out-string    "[*] Details: Citrix Advisories https://fox-it.com/nl/actueel/media/fox-it-citrix-advisory-update/"
                            out-string    "#####################################################################################"
                    fi
                }

            get_nobody_activities()

                {
                    NOBODY_BASH_LOGS="`grep -E ":\ nobody.*\ shell_command" /var/log/bash.log  2>/dev/null`"
                    NOBODY_BASH_LOGS_GZ="`zgrep -E ":\ nobody.*\ shell_command" /var/log/bash.log.*.gz  2>/dev/null`"
                    if [[ ! ( -z "$NOBODY_BASH_LOGS" && -z "$NOBODY_BASH_LOGS_GZ" ) ]] 
                        then
                            out-string    "########################## [bash.log* nobody activities] ############################"
                            out-string    "$NOBODY_BASH_LOGS"
                            out-string    "$NOBODY_BASH_LOGS_GZ"
                            out-string    "#####################################################################################"
                    fi
                }
            
            get_unknown_nobody_process()

                {
                    NOBODY_S_PROC=`ps aux | awk -F " " '$1 ~ "nobody" && $NF !~ "/bin/httpd$" {print $0}'`
                    if [[ ! -z "$NOBODY_S_PROC" ]]
                        then
                            out-string    "############################# [nobody unkown processes] #############################"
                            out-string    "$NOBODY_S_PROC"
                            out-string    "#####################################################################################"
                    fi

                }

            get_nobody_backdoors()

                {
                    POSSIBLE_NOBODY_WEBSHELLS_AND_PL="`find / ! \( -regex '^/dev/.*' -o -regex '^/proc/.*' \) -a \( -regex '.*\.pl$' -o -regex '.*\.php$' \) -user nobody -type f -newerct $MINTIMESTAMP -ls 2>/dev/null`"
                    POSSIBLE_NOBODY_MODIFIED_PHP_AND_PL="`find / ! \( -regex '^/dev/.*' -o -regex '^/proc/.*' \) -a \( -regex '.*\.pl$' -o -regex '.*\.php$' \) -user nobody -type f -newermt $MINTIMESTAMP -ls 2>/dev/null`"
                    if [[ ! -z "$POSSIBLE_NOBODY_WEBSHELLS_AND_PL" ]]
                        then
                            out-string    "#################### [possible nobody webshells and perl scripts] ###################"
                            out-string    "$POSSIBLE_NOBODY_WEBSHELLS_AND_PL"
                            out-string    "#####################################################################################"
                    fi
                    if [[ ! -z "$POSSIBLE_NOBODY_MODIFIED_PHP_AND_PL" ]]
                        then
                            out-string    "############# [possible licit .php/.pl files modified by the attacker] #############"
                            out-string    "$POSSIBLE_NOBODY_MODIFIED_PHP_AND_PL"
                            out-string    "#####################################################################################"
                    fi

                    ### update 20/01/2020 , thx to @x1sec https://github.com/x1sec/CVE-2019-19781/blob/master/CVE-2019-19781-DFIR.md
                    ### (not tested)
                    ### if necessary I will integrate this check
                    ### these should be the exploitable paths by nobody:
                    #
                    #/netscaler/portal/admin/scripts/
                    #/netscaler/portal/scripts/
                    #/netscaler/portal/supporting_files/
                    #/var/netscaler/gui/vpn/scripts/linux
                    #/var/netscaler/gui/vpns/help
                    #/var/netscaler/gui/vpns/scripts/mac
                    #/var/ns_gui/n_top
                    #/var/ns_gui/shared
                    #/var/ns_gui/support
                    #/var/vpn/theme
                    #/var/vpn/themes


                    


                }
            
            get_nobody_crons()

                {
                    NOBODYTAB="`find /var/cron/tabs/nobody -type f -newerct $MINTIMESTAMP -ls 2>/dev/null`"
                    NOBODY_CRONJOBS="`find /var/cron/tabs/nobody -type f -newerct $MINTIMESTAMP -cat {} + 2>/dev/null | grep -vE '^#'`"
                    NOTROBIN_CHECK="` echo "$NOBODY_CRONJOBS" | fgrep '/var/nstmp/.nscache/httpd'`"
                    if [[ ! -z "$NOBODYTAB" ]]
                        then
                            out-string    "################################# [nobody cronjobs] #################################"
                            out-string    "$NOBODYTAB"
                            out-string    "$NOBODY_CRONJOBS"
                            out-string    ""
                            if [[ ! -z "$NOTROBIN_CHECK" ]]
                                then
                                    out-string    "[!] NOTROBIN cronjob found: $NOTROBIN_CHECK"
                                    out-string    '[*] Details: https://www.fireeye.com/blog/threat-research/2020/01/vigilante-deploying-mitigation-for-citrix-netscaler-vulnerability-while-maintaining-backdoor.html'
                                    out-string    ""
                            fi
                            if [[ ! -z "$NOBODY_CRONJOBS" ]]
                                then
                                    out-string    '[!] Please manually check and clean nobody unknown cronjobs:'
                                    out-string    '[*] Run this command to delete all nobody cronjobs:'
                                    out-string    '    crontab -u nobody -r -f'
                                    out-string    '[*] Run this command to delete a specific cronjob:'
                                    out-string         'crontab -u nobody -l | fgrep -v "<unique pattern of malicious task>"  | crontab -u nobody -'
                            fi
                            out-string    "#####################################################################################"                    
                    fi
                }

            get_cve_probing()

                {
                    PROBING="`grep -iE '/vpns/cfg/smb.conf' /var/log/httpaccess.log 2>/dev/null | grep -vE '^127\.0\.0\.1'`"
                    PROBING_GZ="`zgrep -iE '/vpns/cfg/smb.conf' /var/log/httpaccess.log.*.gz 2>/dev/null | grep -vE '^127\.0\.0\.1'`"

                    if [[ ! ( -z "$PROBING_GZ" && -z "$PROBING" ) ]] 
                        then
                            out-string    "############### [httpaccess.log* CVE-2019-19781 probing to smb.conf] ################"
                            out-string    "$PROBING"
                            out-string    "$PROBING_GZ"
                            out-string    "#####################################################################################"
                    fi

                }

            get_xml_and_nsconf_infos()

                {
                    XML_ARTIFACTS="`find / ! \( -regex '^/dev/.*' -o -regex '^/proc/.*' -o -regex '^/flash/.*' \) -a -regex '.*\.xml$' -user nobody -type f -newerct $MINTIMESTAMP -ls 2>/dev/null`"
                    if [[ ! -z "$XML_ARTIFACTS" ]]
                        then
                            out-string    "############################# [Possible .xml artifacts] #############################"
                            out-string    "$XML_ARTIFACTS"
                            out-string    "#####################################################################################"
                    fi

                    XML_CONTENT_m1500="`find / ! \( -regex '^/dev/.*' -o -regex '^/proc/.*' -o -regex '^/flash/.*' \) -a -regex '.*\.xml$' -user nobody -type f -newerct $MINTIMESTAMP -size -1500c -exec cat {} + 2>/dev/null`"
                    XML_CONTENT_M1500_POSSIBLE_OUTPUT_COMMANDS="`find / ! \( -regex '^/dev/.*' -o -regex '^/proc/.*' -o -regex '^/flash/.*' \) -a -regex '.*\.xml$' -user nobody -type f -newerct $MINTIMESTAMP -size +1500c -exec cat {} + 2>/dev/null`"
                    

                    XML_COMMANDS_INSIDE="`echo "$XML_CONTENT_m1500"  | fgrep "template.new({'BLOCK'='" | sed -r "s/.*template.new\(\{'BLOCK'='(.*)%].*/\1/g"| sort | uniq -ic | sort -rnk1`"
                    XML_COMMANDS_IN_NAME="`find / ! \( -regex '^/dev/.*' -o -regex '^/proc/.*' -o -regex '^/flash/.*' \) -a -regex '.*%.*\.xml$' -user nobody -type f -newerct $MINTIMESTAMP -ls 2>/dev/null`"

                    if [[ !  ( -z "$XML_COMMANDS_INSIDE" && -z $XML_COMMANDS_IN_NAME ) ]]
                        then
                            out-string    "############################ [Malicious Commands in .xml] ###########################"
                            if [[ ! -z "$XML_COMMANDS_INSIDE" ]]
                                then
                                    out-string "[*] Overview of command found inside .xml:"
                                    out-string "$XML_COMMANDS_INSIDE"
                                    out-string ""
                            fi
                            if [[ ! -z "$XML_COMMANDS_IN_NAME" ]]
                                then
                                    out-string "[*] Found .xml with command in name:"
                                    out-string "$XML_COMMANDS_IN_NAME"
                                    out-string "[*] Details: https://twitter.com/mpgn_x64/status/1216787131210829826"
                            fi
                            out-string    "#####################################################################################"
                    fi

                    NSCONF_IN_XML="`echo "$XML_CONTENT_M1500_POSSIBLE_OUTPUT_COMMANDS" | fgrep -i -- ' -encrypted ' |  grep -E "(ENCMTHD_(2|3))|\ -hashmethod " | sort | uniq -ic | sort -rnk1 | sed -r "s/[a-zA-Z0-9]{49,}/[THIS_IS_A_HASHED_OR_ENCRYPTED_PASSWORD_CENSORED_BY_THIS_SCRIPT]/g"`"
                    XML_NSCONF_ADVANCED_EXFILTRATION="` echo "$XML_CONTENT_m1500" | grep -E "title.*FILE.*ns\.conf"`"

                    if [[ ! ( -z "$NSCONF_IN_XML" && -z "$XML_NSCONF_ADVANCED_EXFILTRATION" ) ]]
                        then
                            out-string    "####################### [ns.conf exfiltration attempts found] #######################"
                            out-string    "[!] ns.conf in xml commands:"
                            out-string    "$NSCONF_IN_XML"
                            out-string    ""
                            # @msandbu <bookmark UI_inuse="" descr="b:" title="@FILE@[% USE mydata = datafile('/nsconfig/ns.conf', delim = '') %]
                            #[% FOREACH line = mydata %][% FOREACH value = line.values() %][% value %]@BR@[% END %] [% END %]@FILE@" url="http://
                            out-string    "[!] nc.conf advanced exfiltration attempt found:"
                            out-string    "$XML_NSCONF_ADVANCED_EXFILTRATION"
                            out-string    "[*] Details: https://twitter.com/msandbu/status/1215959733900840963"
                            out-string    "#####################################################################################"
                    fi
                    CHECK_NSCONF_ATIME="`find /flash/nsconfig/ns.conf /nsconfig/ns.conf -newerat $MINTIMESTAMP -ls 2>/dev/null`"
                    if [[ ! -z "$CHECK_NSCONF_ATIME" ]]
                        then
                            out-string    "############################### [Recent ns.conf atime] ##############################"
                            out-string    "This file was accessed within atime:"
                            out-string    "$CHECK_NSCONF_ATIME"
                            out-string    "#####################################################################################"
                    fi
                    
                    NSCONF_SENSITIVE_CONTENT="`find /flash/nsconfig/ns.conf /nsconfig/ns.conf -exec cat {} + 2>/dev/null | fgrep ' -encrypted ' | sed -r "s/[a-zA-Z0-9]{49,}/[THIS_IS_A_HASHED_OR_ENCRYPTED_PASSWORD_CENSORED_BY_THIS_SCRIPT]/g" `"
                    CRACKABLE_HASHES="`echo "$NSCONF_SENSITIVE_CONTENT" | fgrep -i -- ' -hashmethod ' | sort | uniq -ic | sort -rnk1`"
                    ENCRYPTED_WITH_HARDCODED_KEYS="`echo "$NSCONF_SENSITIVE_CONTENT" | grep -E 'ENCMTHD_(2|3)' | sort | uniq -ic | sort -rnk1`"

                    if [[ ! -z "$NSCONF_SENSITIVE_CONTENT" ]]
                        then
                            out-string    "######################### [dangerous credentials in ns.conf] ########################"
                            out-string    "[!] it would be good to change all these credentials found in the ns.conf file:"
                            out-string    ""
                            out-string    "$NSCONF_SENSITIVE_CONTENT"
                            out-string    ""
                            if [[ ! -z "$CRACKABLE_HASHES"  ]]
                                then
                                    out-string    "[!!] crackable hashes were found, it is strictly recommended to change these credentials:"
                                    out-string    ""
                                    out-string    "$CRACKABLE_HASHES"
                                    out-string    ""
                                    out-string    "[*] Details: https://twitter.com/buffaloverflow/status/1216807963974938624"
                                    out-string    "[*] Details: https://twitter.com/hashcat/status/440865239597207552"
                                    out-string    ""
                            fi
                            if [[ ! -z "$ENCRYPTED_WITH_HARDCODED_KEYS"  ]]
                                then
                                    out-string    "[!!!] encrypted password with hardcoded keys were found:"
                                    out-string    ""
                                    out-string    "$ENCRYPTED_WITH_HARDCODED_KEYS"
                                    out-string    ""
                                    out-string    "[*] Details: https://dozer.nz/citrix-decrypt/"
                            fi

                            out-string    "#####################################################################################"
                    fi
            }

            get_ioe()
                {
                    # update 20/01/2020 , thanks to @x1sec https://github.com/x1sec/CVE-2019-19781/blob/master/CVE-2019-19781-DFIR.md
                    WEBSHELL_EXPLOITATION="`grep -iE '(support|shared|n_top|vpn|themes).+\.php HTTP/1\.1\" 200' /var/log/httpaccess.log 2>/dev/null`"
                    WEBSHELL_EXPLOITATION_GZ="`zgrep -iE '(support|shared|n_top|vpn|themes).+\.php HTTP/1\.1\" 200' /var/log/httpaccess.log.*.gz 2>/dev/null`"
                    if [[ ! ( -z "$WEBSHELL_EXPLOITATION" && -z "$WEBSHELL_EXPLOITATION_GZ" ) ]]
                        then
                            out-string    "################### [httpaccess.log* Webshell Exploitation (.php)] ##################"
                            out-string    "$WEBSHELL_EXPLOITATION"
                            out-string    "$WEBSHELL_EXPLOITATION_GZ"
                            out-string    "#####################################################################################"
                    fi

                    CVE_EXPLOITATION_PL="`grep -iE '(POST|GET).*\.pl HTTP/1\.1\" 200' -A 1 /var/log/httpaccess.log 2>/dev/null`"
                    CVE_EXPLOITATION_PL_GZ="`zgrep -iE '(POST|GET).*\.pl HTTP/1\.1\" 200' -A 1 /var/log/httpaccess.log.*.gz 2>/dev/null`"
                    if [[ ! ( -z "$CVE_EXPLOITATION_PL" && -z "$CVE_EXPLOITATION_PL_GZ" ) ]]
                        then
                            out-string    "# [httpaccess.log* CVE-2019-19781 Exploitation (.pl) and malicious scripts dropped] #"
                            out-string    "$CVE_EXPLOITATION_PL"
                            out-string    "$CVE_EXPLOITATION_PL_GZ"
                            out-string    "#####################################################################################"
                    fi
                    
                    CVE_EXPLOITATION_XML="`zgrep -iE 'GET.*\.xml HTTP/1\.1\" 200' -B 1 /var/log/httpaccess.log.*.gz 2>/dev/null | fgrep -v ' /vpn/pluginlist.xml '`"
                    CVE_EXPLOITATION_XML_GZ="`zgrep -iE 'GET.*\.xml HTTP/1\.1\" 200' -B 1 /var/log/httpaccess.log.*.gz 2>/dev/null | fgrep -v ' /vpn/pluginlist.xml '`"
                    if [[ ! ( -z "$CVE_EXPLOITATION_XML"  && -z "$CVE_EXPLOITATION_XML_GZ" ) ]]
                        then
                            out-string    "############### [httpaccess.log* CVE-2019-19781 Exploitation (.xml)] ################"
                            out-string    "$CVE_EXPLOITATION_XML"
                            out-string    "$CVE_EXPLOITATION_XML_GZ"
                            out-string    "#####################################################################################"
                    fi
                }
            

            get_unknown_services
            get_outbound_connections
            check_aws_default_credentials
            get_nobody_activities
            get_unknown_nobody_process
            get_nobody_backdoors
            get_nobody_crons
            get_cve_probing
            get_xml_and_nsconf_infos
            get_ioe
        }

    advanced_seeker()

        {
            #### Note: for time reasons all the checks have not been implemented
            ### this part should try to identify any privilege escalations and nobody_seeker evasions

            get_nobody_recents()
                {
                    ALL_NOBODY_RECENTS_FILES="`bash -c "$all_nobody_recents_files_find"`"
                    if [[ ! -z "$ALL_NOBODY_RECENTS_FILES" ]]
                        then
                            out-string    "############################# [all nobody recent files] #############################"
                            out-string    "$ALL_NOBODY_RECENTS_FILES"
                            out-string    "#####################################################################################"
                    fi
                }

            get_files_owned_by_unknown_users()
                {
                    FILES_OWNED_BY_UNKNOWN_USERS="`find / ! \( -regex '^/dev/.*' -o -regex '^/proc/.*' \) -nouser ! -uid 1003 ! -uid 1001 ! -uid 66 ! -uid 501 -ls 2>/dev/null`"
                    if [[ ! -z "$FILES_OWNED_BY_UNKNOWN_USERS" ]]
                        then
                            out-string    "########################### [Files owned by unknown users] ##########################"
                            out-string    "$FILES_OWNED_BY_UNKNOWN_USERS"
                            out-string    "#####################################################################################"
                    fi
                }

            get_bad_users()
                {
                    BAD_USERS="`grep -E ":0+" /etc/passwd | grep -Ev '^(root|nsroot):'`"
                    if [[ ! -z "$BAD_USERS" ]]
                        then
                            out-string    "#################################### [Bad users] ####################################"
                            out-string    "$BAD_USERS"
                            out-string    "#####################################################################################"
                    fi
                }

            get_unknown_writable_root_files()
                {
                    UNKNOWN_WRITABLE_ROOT_FILES="`bash -c "$unknown_writable_root_file_find"`"
                    if [[ ! -z "$UNKNOWN_WRITABLE_ROOT_FILES" ]]
                        then
                            out-string    "###################### [Unknown writable files owned by root] #######################"
                            out-string    "$UNKNOWN_WRITABLE_ROOT_FILES"
                            out-string    "#####################################################################################"
                    fi                    
                }

            get_nobody_group_files()
                {
                    NOBODY_GROUP_FILES="`find / ! \( -regex '^/dev/.*' -o -regex '^/proc/.*' -o -regex '^/var/core/.*' -o -regex '^/var/nstmp/monitors/.*' \) -group nobody 2>/dev/null`"
                    if [[ ! -z "$NOBODY_GROUP_FILES" ]]
                        then
                            out-string    "############################### [Nobody group files] ################################"
                            out-string    "$NOBODY_GROUP_FILES"
                            out-string    "#####################################################################################"
                    fi  
                }

            get_unknown_suid_sgid_files()
                {
                    SUID_SGID="`find / -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null`"
                    DIFF_SUID_SGID="`echo "$SUID_SGID" | grep -Ev "$SUID_SGID_REGEX"`"
                    if [[ ! -z "$DIFF_SUID_SGID" ]]
                        then
                            out-string    "############################# [Unknown suid sgid files] #############################"
                            out-string    "$DIFF_SUID_SGID"
                            out-string    "#####################################################################################"
                    fi                      

                }

            get_startup_scripts()
                {
                    START_SCRIPTS_USERPROFILES="`find /root/ /home/ \( -regex "^.*/\..*profile$" -o -regex "^.*/\..*rc$" -o -regex "^.*/\..*login$" -o -regex "^.*/\..*_logout$" \)  -type f -newerct $MINTIMESTAMP -ls 2>/dev/null`" 
                    START_SCRIPTS="`find / -maxdepth 1 \( -regex "^.*/\..*profile$" -o -regex "^.*/\..*rc$" -o -regex "^.*/\..*login$" -o -regex "^.*/\..*_logout$" \)  -type f -newerct $MINTIMESTAMP -ls 2>/dev/null`"
                    if [[ ! ( -z "$START_SCRIPTS_USERPROFILES" && -z "$START_SCRIPTS" ) ]]
                        then
                            out-string    "################################# [Startup scripts] #################################"
                            out-string    "[!] these files should not exist:"
                            out-string    ""
                            out-string    "$START_SCRIPTS_USERPROFILES"
                            out-string    "$START_SCRIPTS"
                            out-string    "#####################################################################################"
                    fi
                }

            get_ssh_authorized_keys()
                {
                    SSH_AUTHORIZED_KEYS="/root/.ssh/authorized_keys"
                    SSH_AUTHORIZED_KEYS_CONTENT="`cat $SSH_AUTHORIZED_KEYS 2>/dev/null`"
                    if [[ -e "$SSH_AUTHORIZED_KEYS" ]]
                        then
                            out-string    "############################### [SSH authorized keys] ###############################"
                            out-string    "[!] This file should not be here: `ls -l $SSH_AUTHORIZED_KEYS`"
                            out-string    "    Content:"
                            out-string    ""
                            out-string    "$SSH_AUTHORIZED_KEYS_CONTENT"
                            out-string    "#####################################################################################"
                    fi
                }

            get_promisc_interfaces()
                {  
                    PROMISC_INTERFACES="`ifconfig | grep PROMISC`"
                    if [[ ! -z "$PROMISC_INTERFACES" ]]
                        then
                            out-string    "########################### [Interfaces in PROMISC mode] ############################"
                            out-string    "[!] Found interface in PROMISC mode"
                            out-string    ""
                            out-string    "$PROMISC_INTERFACES"
                            out-string    "#####################################################################################"
                    fi                           

                }

            get_cmdlines_from_proc()
                {
                    ### this function could spot a rootkit
                    ALL_PROCESSES="`ps auxd`"
                    CMDLINES_FROM_PROC="`find /proc -name cmdline -exec bash -c "cat {}; echo" \; | tr '\000' ' ' | grep -vE '^$' | sort | uniq`"
                    not_match_counter=0
                    while read CMDLINE
                        do
                            MATCH="`echo "$ALL_PROCESSES" | fgrep -- "$CMDLINE"` | fgrep -v 'find /proc -name cmdline -exec bash -c cat {}; echo ;'"
                            if [ ! "$MATCH" ]
                                then
                                    not_match_counter=$(( $not_match_counter + 1 ))
                                    if [[ $not_match_counter == 1 ]]
                                        then
                                            out-string    "############################ [Possible hidden processes] ############################"
                                            out-string    "[!] Cmdline not found in ps auxd: $CMDLINE"
                                    fi
                                
                            fi
                        done <<<"$(echo "$CMDLINES_FROM_PROC")"

                    if [[ $not_match_counter -ge 1 ]]
                        then
                            out-string    "#####################################################################################"
                    fi

                }
            
            ### /proc/<>/net not found in citrix freebsd

            get_rc()
                {
                    KNOWN_SERVICES_REGEX="^/etc/rc\.d/(devfs|dscache|ns_raid)$"
                    UNEXPECTED_RC_FILES="`find /usr/local/etc/rc.d /etc/rc.shutdown /etc/rc.conf.d/* 2>/dev/null -l`"
                    RCD="`find /etc/rc.d/* 2>/dev/null | grep -Ev "$KNOWN_SERVICES_REGEX"`"
                    RECENT_RC_CONF="` find /etc/rc.d* /etc/rc /etc/rc.conf /etc/rc.conf.local /etc/rc.subr /etc/defaults/* -type f -a \( -newermt $MINTIMESTAMP -o -newerct $MINTIMESTAMP \) -ls 2>/dev/null`"

                    if [[ ! -z $UNEXPECTED_RC_FILES || ! -z $RCD || ! -z $RECENT_RC_CONF ]]
                        then
                            out-string    "################################### [rc.d System] ###################################"
                            if  [[ ! -z $RCD ]]
                                then
                                    out-string    "[!!!] Unknown services found:"
                                    out-string    "$RCD"
                                    out-string    ""
                            fi
                            if  [[ ! -z $UNEXPECTED_RC_FILES ]]
                                then 
                                    out-string    "[!] These files should not exist:"
                                    out-string    "$UNEXPECTED_RC_FILES"
                                    out-string    ""
                            fi
                            if  [[ ! -z $RECENT_RC_CONF ]]
                                then
                                    out-string    "[!] RC files with recent mtime/ctime:"
                                    out-string    "$RECENT_RC_CONF"
                            fi
                            out-string    "#####################################################################################"
                    fi


                }

            get_loader()
                {
                    RECENT_LOADER_CONF="`find /flash/boot/defaults/loader.conf /flash/boot/loader.conf -type f -newermt $MINTIMESTAMP -ls 2>/dev/null`"
                    LOADER_CONF_CONTENT="`find /flash/boot/defaults/loader.conf /flash/boot/loader.conf -type f -newermt $MINTIMESTAMP -exec cat {} 2>/dev/null | grep -Ev '^#'`"
                    UNEXPECTED_LOADER_LOCATION="`find /boot/defaults/loader.conf /boot/loader.conf -type f -ls 2>/dev/null`"

                    if [[ ! -z $UNEXPECTED_LOADER_LOCATION || ! -z $RECENT_LOADER_CONF ]]
                        then
                            out-string    "################################### [loader.conf] ###################################"
                            if  [[ ! -z $UNEXPECTED_LOADER_LOCATION ]]
                                then 
                                    out-string    "[!] These files should not exist:"
                                    out-string    "$UNEXPECTED_LOADER_LOCATION"
                                    out-string    ""
                            fi
                            if  [[ ! -z $RECENT_LOADER_CONF ]]
                                then
                                    out-string    "[!] loader.conf files with recent mtime:"
                                    out-string    "$RECENT_LOADER_CONF"
                                    out-string    ""
                                    if  [[ ! -z $LOADER_CONF_CONTENT ]]
                                        then
                                            out-string    "Content:"
                                            out-string    "$LOADER_CONF_CONTENT"
                                    fi
                            fi
                            out-string    "#####################################################################################"
                    fi
                }
            
            is_sudo_installed()
                {
                    PATH_TO_SUDO="`which sudo`"
                    SUDO_CONF="`find /etc/sudoers* -ls 2>/dev/null`"

                    if [ "$PATH_TO_SUDO" ]
                        then
                            out-string    "####################################### [sudo] ######################################"  
                            out-string    "[!] $PATH_TO_SUDO should not be installed"
                            
                            if [ ! -z "$SUDO_CONF" ]
                                then
                                        out-string "[!] sudo conf file found:"
                                        out-string "$SUDO_CONF"
                            fi
                            out-string    "#####################################################################################"
                    fi
                }

            is_doas_installed()
                {
                    PATH_TO_DOAS="`which doas`"
                    DOAS_CONF="`find /etc/doas.conf* -ls 2>/dev/null`"

                    if [ "$PATH_TO_DOAS" ]
                        then
                            out-string    "####################################### [doas] ######################################"  
                            out-string    "[!] $PATH_TO_DOAS should not be installed"
                            
                            if [ ! -z "$DOAS_CONF" ]
                                then
                                        out-string "[!] doas conf file found:"
                                        out-string "$DOAS_CONF"
                            fi
                            out-string    "#####################################################################################"
                    fi
                }

            is_at_installed()
                {
                    PATH_TO_AT="`which at`"
                    AT_JOBS="`find /var/at/jobs/* ! -regex "/var/at/jobs/\..*" -exec cat {} + 2>/dev/null`"

                    if [[ ! -z "$PATH_TO_AT" ]]
                        then
                            out-string    "################################ [AT scheduled jobs] ################################"  
                            out-string    "[!] $PATH_TO_AT should not be installed"
                            
                            if [ ! -z "$AT_JOBS" ]
                                then
                                        out-string "[!] AT Jobs found:"
                                        out-string "$AT_JOBS"
                            fi
                            out-string    "#####################################################################################"
                    fi

                }

            is_periodic_installed()
                {
                    PATH_TO_PERIODIC_FILES="`find /etc/periodic /usr/local/etc/periodic /etc/periodic.conf /etc/periodic.conf.local /etc/default/periodic.conf -ls 2>/dev/null`"

                    if [[ ! -z "$PATH_TO_PERIODIC_FILES" ]]
                        then
                            out-string    "################################## [Periodic files] #################################"
                            out-string    "[!] periodic should not be installed"
                            out-string    ""
                            out-string    "$PATH_TO_PERIODIC_FILES"
                            out-string    "#####################################################################################"
                    fi  
                }
            
            get_nobody_recents
            get_files_owned_by_unknown_users
            get_bad_users
            get_unknown_writable_root_files
            get_nobody_group_files
            get_unknown_suid_sgid_files
            get_startup_scripts
            get_ssh_authorized_keys
            get_promisc_interfaces
            get_cmdlines_from_proc
            get_rc
            get_loader
            is_sudo_installed
            is_doas_installed
            is_at_installed
            is_periodic_installed


        }

    get_context()
        {
            ALL_PROCESSES="`ps auxd`"
            out-string    "################################# [Simply ps auxd] ##################################"
            out-string    "$ALL_PROCESSES"
            out-string    "#####################################################################################"

            ALL_SOCKETS="`( lsof || sockstat ) 2>/dev/null`"
            out-string    "################################# [lsof or sockstat] ################################"
            out-string    "$ALL_SOCKETS"
            out-string    "#####################################################################################"

            ALL_RECENTS_FILES="`bash -c "$all_users_recents_files_find"`"
            if [[ ! -z "$ALL_RECENTS_FILES" ]]
                then
                    out-string    "############################# [all users recent files] ##############################"
                    out-string    "$ALL_RECENTS_FILES"
                    out-string    "#####################################################################################"
            fi

            CONTENT_OF_POSSIBLE_NOBODY_WEBSHELLS_AND_PL="`find / ! \( -regex '^/dev*' -o -regex '^/proc*' \) -a \( -regex '.*\.pl$' -o -regex '.*\.php$' \) -user nobody -type f -newerct $MINTIMESTAMP -exec bash -c "echo \"[*] content of {}\" ; cat {}" \; 2>/dev/null`"
            CONTENT_OF_POSSIBLE_NOBODY_MODIFIED_PHP_AND_PL="`find / ! \( -regex '^/dev*' -o -regex '^/proc*' \) -a \( -regex '.*\.pl$' -o -regex '.*\.php$' \) -user nobody -type f -newermt $MINTIMESTAMP -exec bash -c "echo \"[*] content of {}\" ; cat {}" \; 2>/dev/null`"
            if [[ ! -z "$CONTENT_OF_POSSIBLE_NOBODY_WEBSHELLS_AND_PL" ]]
                then
                    out-string    "############## [content of possible nobody webshells and perl scripts] ##############"
                    out-string    "$CONTENT_OF_POSSIBLE_NOBODY_WEBSHELLS_AND_PL"
                    out-string    "#####################################################################################"
            fi
            if [[ ! -z "$CONTENT_OF_POSSIBLE_NOBODY_MODIFIED_PHP_AND_PL" ]]
                then
                    out-string    "######## [content of possible licit .php/.pl files modified by the attacker] ########"
                    out-string    "$CONTENT_OF_POSSIBLE_NOBODY_MODIFIED_PHP_AND_PL"
                    out-string    "#####################################################################################"
            fi
        }

    if [ $context ]
        then
            get_context
    fi

    if [[ ( $nobody == 1 || $all == 1 ) ]]
        then
            nobody_seeker
    fi

    if [[ ( $all == 1 ) ]]
    then
        advanced_seeker
    fi
}

threat_seeker
