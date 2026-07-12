## Scenario
A PowerShell process was launched using the ExecutionPolicy Bypass parameter.
- -ExecutionPolicy Bypass is commonly used by administrators to execute scripts without local execution policy restrictions, but it is also frequently observed during malicious PowerShell attacks.

- #### The objective was to determine whether the observed activity was benign or required escalation.

## Investigation
### Step 1 – Identify the Process Creation Event

SPL Query: index=main EventCode=1 Image="*powershell.exe"

### Key observations included:
- User account
- Parent process
- Full command line .. etc

### Step 2 – Review the Command Line
Command observed:
### "C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy Bypass
