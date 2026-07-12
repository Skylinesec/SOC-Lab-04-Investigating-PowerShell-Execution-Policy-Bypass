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
<img width="1351" height="930" alt="Screenshot 2026-07-12 at 18 05 46" src="https://github.com/user-attachments/assets/894ed96c-640a-45c8-b17d-c5f0f62af6be" />

### Step 3 – Investigate Child Processes
Using the Process GUID and Parent Process information, child processes were reviewed.

### Result:
A child process was observed.
No suspicious process execution or malicious binaries were identified.

### Step 4 – Review File Creation Activity
SPL Query:
#### index=main EventCode=11
#### Observed created file: 
<img width="829" height="484" alt="Screenshot 2026-07-12 at 18 46 02" src="https://github.com/user-attachments/assets/4d0eb7e8-46df-41cf-86af-7451ef056245" />

### Step 5 – Review Network Activity
SPL Query:
#### index=main EventCode=3
* A network connection was observed.
* Further investigation found no evidence of malicious destinations or suspicious outbound communication.
<img width="872" height="626" alt="Screenshot 2026-07-12 at 18 54 22" src="https://github.com/user-attachments/assets/ee3967b5-7f7e-47b0-8d03-6314fd7f1022" />

### Step 6 – Review Registry Activity
SPL Query (tried 1 of 3): 
#### index=main (EventCode=12, EventCode=13, EventCode=14)
<img width="821" height="504" alt="Screenshot 2026-07-12 at 19 00 32" src="https://github.com/user-attachments/assets/dc0d04b6-4a8b-4f1b-930a-201746d67d22" />
- Sysmon Event ID 13 showing PowerShell modifying a registry value during execution. The event was correlated with the PowerShell process launched using the -ExecutionPolicy Bypass argument. The registry modification appeared consistent with normal PowerShell runtime behavior, and no persistence-related registry keys were identified.

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

## Severity
#### Medium
Although the use of ExecutionPolicy Bypass warrants investigation due to its common use in an attackers arsenal, the surrounding evidence did not indicate malicious activity. The observed behavior aligned with expected PowerShell execution during legitimate administrative testing.

## Escalation Decision
#### No escalation recommended.
The investigation did not identify indicators of compromise that would justify escalation to a Tier 2 analyst.

## MITRE ATT&CK MAPPING
| Technique                         | ID        |
| --------------------------------- | --------- |
| PowerShell                        | T1059.001 |
| Command and Scripting Interpreter | T1059     |
