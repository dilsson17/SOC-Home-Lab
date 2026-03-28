# T1003.001 - LSASS Dump

## Technique
LSASS memory dumping (MITRE ATT&CK T1003.001)

## What Happened
I simulated credential dumping activity in my lab and reviewed the logs in Splunk. The event data showed suspicious PowerShell activity related to LSASS dumping.

## Logs Observed
- Sysmon Event ID 1
- PowerShell execution
- Suspicious CommandLine activity
- ParentImage

## Detection Query
```spl
index=* EventCode=1 Image="*powershell.exe"
| table _time host User Image CommandLine ParentImage
```

## Why Suspicious
- The command line showed LSASS dump activity
- Tools related to dumping were observed
- PowerShell was used to execute suspicious commands

## Screenshots

### Query Results
![PowerShell Query](../../powershell-query.png)

### Event Details
![LSASS Event](../../powershell-event.png)

## Analyst Takeaway
This activity shows how PowerShell can be used to dump LSASS memory and attempt credential access. Monitoring command line activity is important for detecting this behavior.
