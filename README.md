# VMSA-2023-0001_checker.py
Hunt for vRealize Log Insight VMSA-2023-0001 Exploitation

Run it on a vRealize Log Insight server. Use it to hunt for bad guys. It does not check /usr/lib/loginsight/application/sbin/li-stats.sh modified timestamps. In our testing, the application will change this file's modified times. It's a good idea to track this process and make sure the contents look legitimate. It covers just about everything else.

![](https://assets.aceresponder.com/github/vrealize-checker.png)
