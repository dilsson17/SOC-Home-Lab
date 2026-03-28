# T1547.001 - Startup Persistence

## Technique
Startup folder persistence (MITRE ATT&CK T1547.001)

## What Happened
I simulated persistence in my lab by placing a file in the Startup folder so it could run automatically when the user logs in.

## Logs Observed
- Sysmon Event ID 1
- Sysmon Event ID 11
- File creation activity
- Process execution activity

## Detection Query
```spl
index=* (EventCode=1 OR EventCode=11)
| table _time host User Image TargetFilename CommandLine ParentImage
```

## Why Suspicious
- A file was placed in the Startup folder
- This behavior can be used to maintain persistence after reboot or logon
- File creation and process activity can help identify this technique

## Screenshots
(Add your screenshots here)

## Analyst Takeaway
This activity shows how attackers can use the Startup folder to maintain persistence. Monitoring file creation and related process activity is useful for detecting this behavior.
