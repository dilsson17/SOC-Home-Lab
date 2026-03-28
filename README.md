# SOC Home Lab

## Overview
This is my SOC home lab where I practice detection and investigation using Splunk and Sysmon. I simulate attacks and analyze logs like a real SOC analyst.

## Lab Architecture
- Ubuntu (Splunk SIEM)
- Windows 10 (victim machine with Sysmon)
- Kali Linux (attacker)

Logs from Windows are sent to Splunk using Splunk Universal Forwarder.

## Tools Used
- Splunk
- Sysmon
- Windows Event Logs
- Kali Linux
- MITRE ATT&CK

## Attack Detections
I simulate attacks and create detections based on logs.

- T1059.001 – PowerShell
- T1003.001 – LSASS Dump

## Email Security Gateway (In Progress)
I am building an email security gateway using:
- Postfix
- SpamAssassin
- ClamAV
- Splunk

Goal: detect phishing and malicious emails.

## What I Learned
- How to build a SOC lab
- How logs are generated and analyzed
- How to detect suspicious behavior using Splunk
