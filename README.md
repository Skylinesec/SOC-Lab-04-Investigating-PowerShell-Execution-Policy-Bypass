# SOC-Lab-04-Investigating-PowerShell-ExecutionPolicy-Bypass
### Objective

Investigate a Sysmon Process Creation alert involving PowerShell launched with the -ExecutionPolicy Bypass argument and determine whether the activity represents malicious behavior or legitimate administrative activity.

### Environment
- Splunk Enterprise
- Splunk Universal Forwarder
- Microsoft Sysmon (SwiftOnSecurity Configuration)
- Windows 11
- Sysmon Add-on for Splunk

### Skills Demonstrated
- SIEM Investigation using Splunk
- Sysmon Log Analysis
- Process Creation Analysis
- Parent/Child Process Investigation
- PowerShell Command-Line Analysis
- Network Event Investigation
- Registry Event Investigation
- File Creation Analysis
- Incident Severity Assessment
- MITRE ATT&CK Mapping
- SOC Tier 1 Incident Documentation

### Repository Contents
- Incident Report
- MITRE ATT&CK Mapping
- SPL Queries Used
- Investigation Screenshots

## Investigation Outcome

### Severity: Medium

### Escalation: No

- PowerShell was launched using ExecutionPolicy Bypass during legitimate administrative testing. While registry and network events were observed, no malicious payload execution or persistence mechanisms were identified.

