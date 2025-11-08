# Ransomware Encryption Detection Using Sysmon Events

## Objectives

- Conducted full DFIR on a live Windows victim machine inside TryHackMe’s isolated RDP lab after a ransomware attack that mysteriously “fixed itself.”
- Traced the entire incident from phishing download → encryption → ransom note → attacker RDP panic → decryption → apology note → Bitcoin donation.
- Used only built-in tools (Event Viewer + Sysmon) to reconstruct the timeline, prove the attacker’s mistake, and confirm the system is now clean—all without leaving the victim’s desktop.
- VM: https://tryhackme.com/room/retracted

## Tools Used

- **Windows Event Viewer** (Sysmon Operational → Event ID 1 process, 3 network, 11 file creation)
- **Sysmon logs** (pre-installed, full command lines + hashes)
- **Browser history** (Ctrl+J → Show in folder)
- **Notepad** (ransom note + apology)
- **RDP session** (victim credentials: sophie / fluffy19601234!)

# Investigation

# Task 1: Introduction to Retracted

## A Mother’s Plea (Simulated scenario)

When I began this investigation, I was contacted by Sophie’s mother. She told me that Sophie had downloaded what she thought was an antivirus installer. After running it, all her files became inaccessible, and her wallpaper displayed a ransom message demanding payment in Bitcoin.

Surprisingly, the computer later seemed to return to normal — except for a note asking her to check her Bitcoin wallet. My goal here was to verify if her system was really safe or if remnants of the ransomware were still present.

---

## Connecting to the Machine

To start my analysis, I launched the provided virtual machine.

- Clicked **Start Machine** → waited until it loaded completely.
- This type I connected via **Remote Desktop (RDP)** using:
    
    ```
    Username: sophie
    Password: fluffy19601234!
    IP: MACHINE_IP
    ```
    

Once logged in, I began my forensic investigation.

---

# Task 2: The Message

When I logged into Sophie’s account, I immediately noticed a suspicious text file on the Desktop addressed to her.

This is common behavior for ransomware — they usually drop ransom notes on easily visible locations like the Desktop or Documents folder.

![image.png](image.png)

---

## Step 1: Locate the Message File

I looked at the Desktop and found a file named **SOPHIE.txt**.

![image.png](image%201.png)

So, the **full file path** is:

```
C:\Users\Sophie\Desktop\SOPHIE.txt
```

---

## Step 2: Identify the Program Used to Create the File

I needed to determine which program created this ransom note.

### Tools and Concept:

- **Sysmon (System Monitor)** logs every process creation (Event ID 1).
- **Event Viewer** on Windows stores these logs in
    
    ```
    Application and Services Log/Microsoft/Windows/Sysmon/Operational
    ```
    
    ![image.png](image%202.png)
    

### Investigation:

I first tried Event ID 11 (file creation), but no relevant result appeared.

So, I filtered **Event ID 1** and searched for “SOPHIE.txt”.

Found the event 

![image.png](image%203.png)

The event showed the **CommandLine** used:

![image.png](image%204.png)

```
"C:\Windows\system32\NOTEPAD.EXE" C:\Users\Sophie\Desktop\SOPHIE.txt
```

This confirmed that **Notepad.exe** created the ransom note.

---

## Step 3: Note the Time of File Creation

Checking the event details, the **UTC timestamp** of this process was:

`2024-01-08 14:25:30.749`

---

# Task 3: Something Wrong

Sophie mentioned that the issue began right after she ran a downloaded “antivirus installer.” She believed it was from Google, which made it sound trustworthy — but clearly, it wasn’t.

My next step was to identify the malicious executable she ran and what exactly it did to her system.

---

## Step 1: Identify the Installer Filename

Since Sysmon logs every new process (Event ID 1), I searched for processes executed before the ransom note was created.

![image.png](image%205.png)

A few events earlier, I found one labeled **Decryptor.exe**, which sounded related to ransomware recovery. But Sophie wouldn’t have that — this meant the real malicious installer ran even earlier.

### Concept:

Attackers often disguise ransomware as legitimate software like antivirus installers.

To confirm, I checked the **browser history (Ctrl+H)** and **downloads (Ctrl+J)** in the default browser.

![image.png](image%206.png)

There, I found an entry:

```
antivirus.exe
```

This matched Sophie’s description perfectly.

---

## Step 2: Check the Download Location

By clicking **“Show in Folder”**, I located where the file was saved:

![image.png](image%207.png)

```
C:\Users\Sophie\download
```

---

## Step 3: Identify the File Extension Used After Encryption

When ransomware runs, it usually encrypts files and renames them with a new extension.

To confirm, I searched Sysmon logs for activity related to `antivirus.exe` after clearing filters.

![image.png](image%208.png)

I found a file creation event (Event ID 11) roughly ten minutes before the ransom note was made.

The event showed an Excel file with the new extension `.dmp`.

![image.png](image%209.png)

Even though `.dmp` is normally used for memory dump files, here it was used as the **encryption marker extension** by the malware.

---

## Step 4: Identify the IP Address Contacted

Malware often communicates with a remote **Command and Control (C2)** server.

By looking at Sysmon’s **network connection events** (Event ID 3) for `antivirus.exe`, I found an outbound TCP connection:

![image.png](image%2010.png)

This confirmed that the installer reached out to an external IP — likely the attacker’s C2 server.

**Answer:** `10.10.8.111`

---

# Task 4: Back to Normal

### **Investigation Goal**

I needed to determine how the threat actor logged into the system and what caused everything to appear “normal” again after the supposed infection.

---

### **Step 1: Identify the RDP Login Event**

I searched through the event logs for **RDP (Remote Desktop Protocol)** connections to check for any suspicious login activity.

- **Action:** I filtered the logs using the keyword `RDP`.
- **Observation:** Found an RDP event showing a successful connection.
    
    ![Searching-for-RDP.jpg.webp](Searching-for-RDP.jpg.webp)
    
- **Result:** The connection originated from **source IP `10.11.27.46`**.

---

### **Step 2: Find When the File Was Executed**

Since the incident mentioned an “installer” or a “decryptor,” I searched for the execution of the **decryptor.exe** file.

- **Action:** Searched the logs for the keyword `decryptor.exe`.
- **Observation:** Found an event entry showing when it was executed.
    
    ![image.png](image%2011.png)
    
- **Result:** The file ran on **`2024-01-08 14:24:19.573 UTC`**.

---

### **Concept Summary**

- **RDP Event:** Shows when a remote user connects to a system.
- **Source IP:** Helps trace the origin of a remote session.
- **File Execution Timestamp:** Indicates when a suspicious file or malware was run.

---

# Task 5: Doesn’t Make Sense

### **Goal**

Arrange the sequence of events that happened during the infection and clean-up.

| Event Description | Correct Order |
| --- | --- |
| Sophie downloaded and ran the malware. | **1** |
| The malware encrypted the files and showed a ransom note. | **2** |
| Sophie saw the note and called for help. | **3** |
| The intruder logged in via RDP and looked around. | **4** |
| The intruder realized his mistake and decrypted all files. | **5** |
| He left a message before disconnecting. | **6** |
| We arrived to investigate. | **7** |

### **Final Analysis**

The attacker accidentally infected a **charity organization**. Realizing the mistake, he:

- Logged in remotely.
- Decrypted all the files.
- Left a message.
- Donated Bitcoin to the charity.

---

# Lessons Learned

- Sysmon Event ID 1 + “SOPHIE.txt” in CommandLine = instant ransom-note author (Notepad.exe).
- Browser downloads + Sysmon = perfect phishing ground truth—antivirus.exe from Google was never legit.
- File creation (ID 11) with weird extension (.dmp) = encryption marker even when disguised as memory dumps.
- Outbound TCP from antivirus.exe (ID 3) → 10.10.8.111 = C2 confirmed in one click.
- RDP source IP 10.11.27.46 + decryptor.exe timestamp = attacker panic logon caught red-handed.
- Safe RDP VM + pre-infected box = I just lived through a real ransomware case and watched the attacker back down.

# Socials

**Repository:** https://github.com/RahulCyberX/Endpoint-Security-Monitoring

**Medium Article:** https://medium.com/@rahulcyberx/retracted-endpoint-security-monitoring-thm-2025-605b79a8cf6c?source=your_stories_outbox---writer_outbox_published-----------------------------------------

**TryHackMe Profile:** https://tryhackme.com/p/0xRahuL

**Github Profile:** https://github.com/RahulCyberX