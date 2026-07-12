## Scenario
A PowerShell process was launched using the ExecutionPolicy Bypass parameter.
- -ExecutionPolicy Bypass is commonly used by administrators to execute scripts without local execution policy restrictions, but it is also frequently observed during malicious PowerShell attacks.

- #### The objective was to determine whether the observed activity was benign or required escalation.

## Investigation
### Step 1 – Identify the Process Creation Event
SPL Query: 
#### index=main EventCode=1 Image="*powershell.exe"

#### Key observations included:
- User account
- Parent process
- Full command line .. etc

### Step 2 – Review the Command Line
Command observed:
#### "C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy Bypass

### Step 3 – Investigate Child Processes
Using the Process GUID and Parent Process information, child processes were reviewed.

### Result:
A child process was observed.
No suspicious process execution or malicious binaries were identified.

### Step 4 – Review File Creation Activity
SPL Query:
#### index=main EventCode=11

Observed created file: 
#### C:\Users\jetro\AppData\Local\Microsoft\CLR_v4.0\UsageLogs\powershell.exe.log

### Step 5 – Review Network Activity
SPL Query:
#### index=main EventCode=3
* A network connection was observed.
* Further investigation found no evidence of malicious destinations or suspicious outbound communication.

### Step 6 – Review Registry Activity
SPL Query (tried 1 of 3): 
#### index=main (EventCode=12, EventCode=13, EventCode=14)

## Evidence Collected
| Artifact          | Result              |
| ----------------- | ------------------- |
| User              | Jetros-Laptop\jetro |
| Process           | powershell.exe      |
| Execution Policy  | Bypass              |
| Process Creation  | Yes                 |
| Child Process     | Yes                 |
| File Creation     | CLR Usage Log       |
| Network Activity  | Yes                 |
| Registry Activity | Yes                 |
| Malicious Payload | Not Observed        |
| Persistence       | Not Observed        |
| Credential Access | Not Observed        |

## Analyst Assessment
PowerShell was launched interactively by the logged-in user using the -ExecutionPolicy Bypass parameter.
During execution, expected administrative commands were performed. Telemetry showed normal PowerShell artifacts, including a CLR usage log, registry activity, and a network connection. No malicious payloads, persistence mechanisms, credential access, or suspicious child processes were identified.
Based on the available evidence, the observed activity is consistent with legitimate administrative testing rather than malicious behavior.
