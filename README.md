# VMSA-2023-0001_checker.py

![](https://assets.aceresponder.com/aceresponder-logo.png)

This script checks for vRealize Log Insight VMSA-2023-0001 exploitation artifacts.

Run it on a vRealize Log Insight server. Use it to hunt for bad guys. It does not check /usr/lib/loginsight/application/sbin/li-stats.sh modified timestamps. In our testing, the application will change this file's modified times randomly. It's a good idea to peek at this file and make sure the contents look legitimate. It covers just about everything else.

![](https://assets.aceresponder.com/github/vrealize-checker.png)
