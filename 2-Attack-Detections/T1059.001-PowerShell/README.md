## Technique
PowerShell execution (MITRE ATT&CK T1059.001)

## What Happened
I simulated suspicious PowerShell activity in my lab and reviewed the logs in Splunk.

## Logs Observed
- Sysmon Event ID 1
- PowerShell process activity
- CommandLine
- ParentImage

## Detection Query
```spl
index=* EventCode=1 Image="*powershell.exe"
| table _time host User Image CommandLine ParentImage
```

## Why Suspicious
- PowerShell was used to run suspicious commands
- The command line showed unusual activity
- Parent-child process behavior can help identify malicious execution

## Screenshots

### Detection Query in Splunk
![PowerShell Query](../../powershell-query.png)

### Event Details
![PowerShell Event](../../powershell-event.png)

## Analyst Takeaway
This activity shows how PowerShell can be used in attacks. Looking at command line activity and process details is important for detection.
