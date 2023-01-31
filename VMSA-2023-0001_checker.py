#!/usr/bin/python
import re
import os
import datetime

print("ACE Responder VMSA-2023-0001 Exploitation Checker")
print("This script will check for VMSA-2023-0001 Exploitation on VMWare vRealize Log Insight servers.")
print()

print("[i] .pak files in /tmp. Check for legitimacy:")
paks = os.listdir('/tmp/')
for p in paks:
    if p.endswith('.pak'):
        print(p)

print()

print("[i] Checking for events in runtime.log. Check to see if the source and file are legitimate!")
print()


remote_pak_pattern = re.compile('^\[([^\]]+)\].*REMOTE_PAK_DOWNLOAD_COMMAND.*requestUrl:([^,]+), fileName:([^\)]+)')
with open('/var/log/loginsight/runtime.log') as f:
    for line in f:
        match = re.search(remote_pak_pattern, line)
        if match:
            print('\033[93m[+] REMOTE_PAK_DOWNLOAD on ' + match.group(1) + ' from ' + match.group(2) + ' to ' + match.group(3) + '\033[0m')
            if match.group(3).startswith('../'):
                print('\033[91m\t [!] directory traversal CVE-2022-31706 Exploitation identified! Indicators: '+match.group(2) +' ' + match.group(3)+ '\033[0m')


print()
print("[i] Checking /usr/lib/loginsight/application/sbin timestamps. If loginsight-pak-upgrade.py was updated on a usual date, it could be an indicator of compromise.")

sbin_path = '/usr/lib/loginsight/application/sbin'

def check_mtimes(paths,file):
    files = {}
    popular = {}
    most_popular_count = 0
    most_popular = ''
    for path in paths:
        for fil in os.listdir(path):
            mtime = os.path.getmtime(path+'/'+fil)
            dt_mod = datetime.datetime.fromtimestamp(mtime)
            day = dt_mod.strftime("%Y%m%d")
            files[fil] = day
            if day not in popular.keys():
                popular[day] = 1
            else:
                popular[day] += 1
        for pop in popular.keys():
            if popular[pop] > most_popular_count:
                most_popular_count = popular[pop]
                most_popular = pop
    if files[file] != most_popular:
        print('\033[93m[+] Unusual file modification date '+files[file]+' for '+ file +' most have the date '+most_popular+ '\033[0m')


check_mtimes([sbin_path],'loginsight-pak-upgrade.py')

print()
print("[i] Checking /usr/lib/sa for unusual modified times.")
for t in ['sa1','sa2','sadc']:
    check_mtimes(['/usr/lib/sa'],t)
print()

print("[i] Checking for unusual cron files.")
cron_files = {'daily':['audit-rotate'],'hourly':['0anacron','logrotate'], 'weekly':['devcheck','rpmcheck','sgidcheck','suidcheck']}
for cron_int in cron_files.keys():
    for fil in os.listdir('/etc/cron.'+cron_int):
        if fil not in cron_files[cron_int]:
            print('\033[93m[+] Unusual cron file /etc/cron.'+cron_int+'/'+fil+'\033[0m')


for cron_int in cron_files.keys():
    for cronf in cron_files[cron_int]:
        check_mtimes(['/etc/cron.hourly','/etc/cron.daily','/etc/cron.monthly','/etc/cron.weekly'],cronf)
