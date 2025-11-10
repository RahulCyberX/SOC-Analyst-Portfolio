# Memory Forensics and Code Injection - BoogeymanP2

## Objectives

- Map **Boogeyman v2** kill chain from spear-phish (**macro DOC**) → stage-2 JS → stage-3 EXE → **C2** → **persistence**.
- Correlate **email**, **macro/VBA**, and **memory forensics** (Volatility) to attribute processes, paths, PIDs, and IOCs.
- Confirm **persistence mechanism** (scheduled task + registry-stored, Base64-encoded PS payload).

## Tools Used

- **VM -** [https://tryhackme.com/room/boogeyman2](https://tryhackme.com/room/boogeyman2)
- **Thunderbird** – header/body triage; attachment handling.
- **olevba** – extract/inspect VBA: stage-2 fetch to `update.js`, execution via **wscript**.
- **Volatility 3** – `windows.pstree`, `windows.netscan`, `windows.dlllist`, `windows.filescan` to trace `wscript.exe` (PID **4260**, PPID **1124**), `updater.exe` path & C2.
- **strings + grep** – pull URLs (`files.boogeymanisback.lol`), scheduled task command, and cache path for the DOC.
- **Core CLI** – hashing (`md5sum`), general parsing.

---

# [Investigation]

# Task 1: [Introduction]

After the severe attack carried out by the Boogeyman threat actor in the previous incident, **Quick Logistics LLC** significantly enhanced its **security defences**. However, despite the improvements, the **Boogeyman group has resurfaced**—this time deploying **new and advanced tactics, techniques, and procedures (TTPs)** designed to evade detection and achieve deeper compromise.

![image.png](image.png)

In this new phase of the investigation, I was tasked to analyze and document the **updated attack workflow** of the Boogeyman group, focusing on how their methods evolved since the first campaign.

## Investigation Setup

Before beginning the investigation, I deployed the **attached virtual machine** by selecting the **Start Machine** option on the TryHackMe platform. After waiting a few minutes for initialization, the analysis environment became available in split-screen mode, allowing me to interact directly with the virtualized system.

## Provided Artefacts

For this analysis, I was provided with the following artefacts located in the directory:

`/home/ubuntu/Desktop/Artefacts`

| Artefact | Description |
| --- | --- |
| **Phishing Email** | Copy of the phishing message that initiated the compromise. |
| **Memory Dump (memorydump.raw)** | Volatile memory capture from the victim’s workstation containing live artefacts from the attack. |

## Tools Utilized

The investigation environment included specialized forensic and malware analysis tools to facilitate artefact examination:

### **1. Volatility**

An open-source digital forensics framework used for analyzing **volatile memory (RAM)**. With Volatility, I extracted system artefacts such as processes, command executions, loaded modules, and potential indicators of persistence.

**Basic usage syntax:**

```bash
vol -f memorydump.raw <plugin>
```

To list all available plugins for Volatility analysis:

```bash
vol -f memorydump.raw -h
```

Since parsing a memory dump can be time-consuming, I allowed sufficient time for the plugins to load and complete each query.

### **2. Olevba**

A tool from the **Oletools suite**, used for analyzing and extracting **VBA macros** from Microsoft Office documents. I used this tool to inspect the phishing document for embedded malicious macros or scripts responsible for executing payloads.

**Usage example:**

```bash
olevba document.doc
```

---

# Task 2: [Spear Phishing] – Human Resources

The **Boogeyman threat actor** has returned, this time targeting another employee within **Quick Logistics LLC** — **Maxine**, a Human Resource Specialist. Maxine received what appeared to be a legitimate **job application email** containing an attached **resume document**. However, the attached file was **malicious**, and upon opening it, her workstation became compromised.

## Incident Overview

This incident marked a shift in the Boogeyman group’s targeting strategy. In their previous campaign, the attackers focused on the **finance department**, while in this case, they expanded their reach to the **Human Resources division**, using a spear-phishing email tailored specifically for HR-related operations.

The email was crafted to appear genuine, leveraging realistic content related to the hiring process. The attachment, disguised as a resume, was embedded with **malicious macros or scripts** that executed upon opening, granting the attacker initial access to the workstation.

![image.png](image%201.png)

## Detection and Response

The **security team** at Quick Logistics LLC promptly detected **suspicious PowerShell command executions** originating from Maxine’s system. These activities were consistent with known Boogeyman techniques used in earlier campaigns.

The alerts triggered an **incident response investigation**, during which I was assigned to analyze and determine the impact of the compromise.

## Investigation

### What email was used to send the phishing email?

![image.png](image%202.png)

Answer: `westaylor23@outlook.com`

### What is the email of the victim employee?

![image.png](image%203.png)

Answer: `maxine.beck@quicklogisticsorg.onmicrosoft.com`

### What is the name of the attached malicious document?

![image.png](image%204.png)

Answer: `Resume_WesleyTaylor.doc`

### What is the MD5 hash of the malicious attachment?

- Save the document on the Desktop.
    
    ![image.png](image%205.png)
    
- Open the terminal.
    
    ![image.png](image%206.png)
    
- Use the following command to get the md5 hash
    
    ![image.png](image%207.png)
    

Answer: `52c4384a0b9e248b95804352ebec6c5b`

### What URL is used to download the stage 2 payload based on the document's macro?

Parse the file with olevba, which is provided in this challenge.

```
olevba Resume_WesleyTaylor.doc
```

![image.png](image%208.png)

![image.png](image%209.png)

It revealed the URL where the payload is being hosted at, and it will save the file as `update.js`.

Answer: `https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png`

### What is the name of the process that executed the newly downloaded stage 2 payload?

In the same olevba result, scroll down to identify the process which executed the the `update.js` payload.

![image.png](image%2010.png)

Answer: `wscript.exe`

### What is the full file path of the malicious stage 2 payload?

It can also be found in the same screenshot:

![image.png](image%2011.png)

Answer: `C:\ProgramData\update.js`

### What is the PID of the process that executed the stage 2 payload?

- So we know the name of the process which executes the payload.
- Now I need to analyze the memory dump of the victim’s workstation and find the PID of `wscript.exe`.
- I will use **Volatility** to see the process tree.
    
    ```
    vol -f WKSTN-2961.raw windows.pstree
    ```
    
    ![image.png](image%2012.png)
    
    Wait for it to complete scanning..
    
    ![image.png](image%2013.png)
    

Answer: `4260`

### What is the parent PID of the process that executed the stage 2 payload?

![image.png](image%2014.png)

Answer: `1124`

### What URL is used to download the malicious binary executed by the stage 2 payload?

- Using the **strings** command to search for strings such as URLs, from the memory. Along with using **grep** to filter the strings that contains the domain name which we found out in a previous question.
    
    ```
    strings WKSTN-2961.raw | grep "boogeymanisback.lol”
    ```
    
    ![image.png](image%2015.png)
    

Answer: `https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.exe`

### What is the PID of the malicious process used to establish the C2 connection?

- For this task I will again use **Volatility**, but this time I need to use it’s **netscan** plugin to analyze the network connections.
    
    ```
    vol -f WKSTN-2961.raw windows.netscan 
    ```
    
    ![image.png](image%2016.png)
    

Answer: `6216`

### What is the full file path of the malicious process used to establish the C2 connection?

- List the **DLLs** which were used by this process (`6216`).
    
    ```
    vol -f WKSTN-2961.raw windows.dlllist --pid 6216
    ```
    
    ![image.png](image%2017.png)
    

Answer: `C:\Windows\Tasks\updater.exe`

### What is the IP address and port of the C2 connection initiated by the malicious binary? (Format: IP address:port)

```
vol -f WKSTN-2961.raw windows.netscan | grep updater.exe
```

![image.png](image%2018.png)

Answer: `128.199.95.189:8080`

### What is the full file path of the malicious email attachment based on the memory dump?

- What I already know:
    - Name of email attachment: `Resume_WesleyTaylor.doc`
- So I am gonna scan for files inside the memory dump of victim’s workstation and grep only the strings that matches the name of the email attachment:
    
    ```
    vol -f WKSTN-2961.raw windows.filescan | grep Resume_WesleyTaylor
    ```
    
    ![image.png](image%2019.png)
    

Answer: `C:\Users\maxine.beck\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\WQHGZCFI\Resume_WesleyTaylor (002).doc`

### The attacker implanted a scheduled task right after establishing the c2 callback. What is the full command used by the attacker to maintain persistent access?

- Look into the memory dump and search for strings containing `schtasks`.
    
    Why? It’s a command responsible for **managing scheduled tasks.**
    
    ```
    strings WKSTN-2961.raw | grep schtasks
    ```
    
    ![image.png](image%2020.png)
    

Answer: `schtasks /Create /F /SC DAILY /ST 09:00 /TN Updater /TR 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\Software\Microsoft\Windows\CurrentVersion debug).debug)))\"`

---

# Lessons Learned

- **Initial Access:** HR-themed spear-phish with **macro DOC** (`Resume_WesleyTaylor.doc`, MD5 `52c4384a0b9e248b95804352ebec6c5b`) remains effective; macros fetch stage-2 from attacker CDN (`/update.png` → saved as `C:\ProgramData\update.js`) and launch via **wscript.exe**.
- **Execution & C2:** Stage-2 retrieves **`update.exe`** (written as `C:\Windows\Tasks\updater.exe`, PID **6216**) and beacons to **`128.199.95.189:8080`**—clear network IOC.
- **Forensic Anchors:** Memory artifacts reliably expose **process tree**, **on-disk paths**, **email cache path** (`INetCache\Content.Outlook\...\Resume_WesleyTaylor (002).doc`), and **network sockets** even when disk artifacts are later cleaned.
- **Persistence:** Attacker used **SCHTASKS** to run a hidden PowerShell loader daily at 09:00, pulling a **Base64** payload from a **HKCU** registry value—blend of LOLBins + registry-backed persistence that evades basic file-based AV.
- **Defenses to Prioritize:**
    - Block/inspect egress to **`files.boogeymanisback.lol`** and **`128.199.95.189:8080`**; add to DNS/HTTP blocklists.
    - Harden **Office macro** policy (block unsigned/internet-origin macros), enable **AMSI/Script Block Logging**, and alert on **`wscript.exe` launching from `ProgramData`** paths.
    - Detections for **scheduled task creation** invoking PowerShell with `W hidden`, `NonI`, and **registry-sourced Base64**.
    - Memory-first IR playbook: Volatility sweeps (`pstree`, `netscan`, `dlllist`, `filescan`) to rapidly fix PIDs/paths/IOCs for containment.

# Socials

**Repository:** https://github.com/RahulCyberX/SOC-Analyst-Portfolio/

**Medium Article:** https://rahulcyberx.medium.com/threat-investigation-boogeyman-2-soc-level-1-capstone-challenge-thm-5328e86d304f?sk=104b1fbe2d669e8efd01c5602c0eaebd

**TryHackMe Profile:** https://tryhackme.com/p/0xRahuL

**Github Profile:** https://github.com/RahulCyberX
