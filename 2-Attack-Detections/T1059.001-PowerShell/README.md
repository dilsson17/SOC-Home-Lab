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
- The command line showed unusual execution behavior
- PowerShell can be abused to execute malicious actions

## Screenshots

### Detection Query in Splunk
![PowerShell Query](../../powershell-query.png)

### Event Details
![PowerShell Event](../../powershell-event.png)

## Analyst Takeaway
This activity shows how PowerShell can be abused for execution in attacks. Reviewing command-line activity and process details is important for detecting suspicious PowerShell behavior.
