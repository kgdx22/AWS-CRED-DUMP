# AWS-CRED-DUMP

## **Step 1: Simulate the Incident**
Open PowerShell as Administrator and run the following command:
> <br />*powershell -EncodedCommand aABpACAAJABFAE4AdgA6AFUAcwBlAHIA*

<br />This is a benign base64-encoded PowerShell command (hi $Env:User) that mimics obfuscation often used in real attacks.

You can also simulate a registry-related command:
>*Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "TestRunKey" -Value "cmd.exe"*

<br />This triggers Sysmon Event ID 13 for registry modifications—often seen in persistence mechanisms.

## **Step 2: Run a Velociraptor Hunt**
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

## **Step 4: Analyze the IOCs**
Use VS Code or Excel (if available) to search for these indicators:

Search Terms:
<br />" *EncodedCommand* "
<br />" *User* "
<br />" *'EventID': 13* "
<br />" *Credential* "
<br />" \\\REGISTRY\\\ "

You should see a process like:
> powershell.exe -EncodedCommand aABpACAAJABFAE4AdgA6AFUAcwBlAHIA
> 
<br /> or

>cmd.exe /c Set-ItemProperty ...
>
These mimic credential dumping or persistence behavior—common tactics in real attacks.
