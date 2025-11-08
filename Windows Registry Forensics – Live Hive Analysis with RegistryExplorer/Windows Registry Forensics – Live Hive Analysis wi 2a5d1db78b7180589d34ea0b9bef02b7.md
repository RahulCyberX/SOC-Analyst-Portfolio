# Windows Registry Forensics – Live Hive Analysis with RegistryExplorer

## Objectives

- Load and parse live Windows registry hives (SAM, SYSTEM, SOFTWARE, NTUSER.DAT) from a compromised workstation using RegistryExplorer.
- Extract user account details, password hints, and account creation metadata from the SAM hive.
- Uncover evidence of execution, recently accessed files, and application run history across user profiles.
- Identify connected USB devices, retrieve friendly names, serial numbers, and precise connection timestamps from SYSTEM and SOFTWARE hives.
- Build a complete forensic timeline of user activity, external device usage, and potential data exfiltration vectors—all in a safe, isolated lab environment.

## Tools Used

- VM: [https://tryhackme.com/room/windowsforensics1](https://tryhackme.com/room/windowsforensics1)
- **RegistryExplorer** (Eric Zimmerman’s tool, run as Administrator)
- **Windows Registry Hives**
    - `C:\\Windows\\System32\\config\\` → SAM, SYSTEM, SOFTWARE
    - `C:\\Users\\<username>\\NTUSER.DAT` → per-user settings
- **Built-in Windows paths**
    - `RecentDocs`, `UserAssist`, `RecentApps`
    - `USBSTOR`, `Windows Portable Devices`
    - `CurrentControlSet\\Enum`

# Investigation

In this hands-on task, I practiced performing a live forensic investigation using **RegistryExplorer** to analyze registry hives and extract information about user accounts, executed files, and connected USB devices from a compromised Windows system.

---

## Step 1 — Loading the Registry Hives

**Tools Used:** RegistryExplorer (run as Administrator)

**Process:**

1. I launched **RegistryExplorer** from the `EZtools` folder as an administrator.
    
    ![image.png](image.png)
    
2. Loaded the following hives from the directory:
    
    ```
    C:\Windows\System32\Config
    ```
    
    ![1_FMk3eEJu0TqDLfmT8OMSVQ.webp](1_FMk3eEJu0TqDLfmT8OMSVQ.webp)
    
    ![image.png](image%201.png)
    
    - SAM
    - SOFTWARE
    - SYSTEM

---

## Step 2 — Investigating User Accounts (SAM Hive)

**Concept:**

The **SAM (Security Accounts Manager)** stores user account information, including usernames and password hashes.

**Findings:**

![1_LD-JscYSLaRSuTvJ3LHeYw.webp](1_LD-JscYSLaRSuTvJ3LHeYw.webp)

- **Number of user-created accounts:** `3`
- **User account never logged in:** `thm-user2`
- **Password hint for user THM-4n6:** `count`

---

## Step 3 — Examining Evidence of Execution (NTUSER.DAT Hive)

**Concept:**

The **NTUSER.DAT** hive stores user-specific information, including recent files accessed and application execution records.

**Process:**

1. Located the hidden file:
    
    ```
    C:\Users\<username>\NTUSER.DAT
    ```
    
    ![1_LlA3RsNjF7uTCNUtmtFebw.webp](1_LlA3RsNjF7uTCNUtmtFebw.webp)
    
2. Unhid it in File Explorer (as it’s hidden by default).
    
    ![image.png](image%202.png)
    
    It’s important to note that making changes directly to the NTUSER.DAT file can be risky and is generally not recommended, as it can lead to corruption or issues with the user's profile. Therefore, in default setting, NTUSER.DAT is a hidden file and in order to access it for this task, I had to unhide it in the File Explorer.
    
3. Loaded it into RegistryExplorer.
    
    ![image.png](image%203.png)
    
4. After NTUSER.DAT is loaded, I can look into recent files by following this path:
    
    ```
    NTUSER.DAT\ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
    ```
    
    ![1_z3H2lSxYPtIE_eMi6Tc_rw.webp](1_z3H2lSxYPtIE_eMi6Tc_rw.webp)
    
5. Found the access record for `Changelog.txt`.
    
    ![image.png](image%204.png)
    

**Finding:**

- **Accessed on:** `2021–11–24 18:18:48`

---

## Step 4 — Investigating Executed Applications

**Concept:**

Windows tracks executed applications through multiple artifacts — UserAssist, ShimCache, AmCache, and BAM/DAM.

**Process & Observation:**

- Checked **UserAssist**, **ShimCache**, **AmCache**, and **BAM/DAM**, but none contained relevant data.
    
    ![1_UOWVlKvSPssg9f_2b6B_Lw.webp](1_UOWVlKvSPssg9f_2b6B_Lw.webp)
    
    ![1_odjxVQAeV6zjYDEEqHfifg.webp](1_odjxVQAeV6zjYDEEqHfifg.webp)
    
- Tried searching “Apps” in the RegistryExplorer search bar → found a key named **RecentApps**.
- Located information about a Python installer execution.

**Finding:**

- **Installer Path:** `Z:\setups\python-3.8.2.exe`

---

## Step 5 — Analyzing USB Device Connections

**Concept:**

The registry stores USB device history under **SYSTEM** and **SOFTWARE** hives, useful for identifying external device usage.

![1_6n9tdOIHQlBAGtiGJ5tcJA.webp](1_6n9tdOIHQlBAGtiGJ5tcJA.webp)

![1_XHUYpGPl1C-u_mIm4oYO4Q.webp](1_XHUYpGPl1C-u_mIm4oYO4Q.webp)

**Process:**

1. Loaded the required file in Registry Explorer from this location:
    
    ```
    C:\Users\THM-4n6\Desktop\triage\C\Windows\System32\config
    ```
    
    ![image.png](image%205.png)
    
2. Started from:
    
    ```
    SOFTWARE: Microsoft\Windows Portable Devices
    ```
    
    ![image.png](image%206.png)
    
    - Found GUID for device with **Friendly Name: USB**
        
        ![image.png](image%207.png)
        
3. Navigated to:
    
    ```
    SYSTEM\CurrentControlSet\Enum\USBSTOR
    ```
    
    ![1_WhrWQlqd82F-vTLNQdkshQ.webp](1_WhrWQlqd82F-vTLNQdkshQ.webp)
    
    - Extracted timestamp details of device connections.
        
        ![1_GaEQfsxV8acipwsBVZLa5w.webp](1_GaEQfsxV8acipwsBVZLa5w.webp)
        

**Finding:**

- **USB device last connected on:** `2021–11–24 18:40:06`

---

## Summary

In this challenge, I analyzed multiple registry artifacts to uncover digital evidence, including:

- User account details (SAM)
- File access records (NTUSER.DAT)
- Executed application traces (RecentApps)
- USB connection history (SYSTEM & SOFTWARE hives)

This exercise strengthened my understanding of **Windows registry forensics** — a critical skill for identifying user activity, external device usage, and potential compromise indicators during an investigation.

### Lessons Learned

- SAM hive → instant view of all local accounts, RID, last login, and password hints (`count` for THM-4n6).
- `thm-user2` with zero logon time = dormant backdoor or staging account.
- NTUSER.DAT\RecentDocs → `Changelog.txt` accessed at **2021-11-24 18:18:48** = precise file interaction timestamp.
- Hidden `NTUSER.DAT` must be unhidden in Explorer to access—never edit live hives directly.
- `RecentApps` key beats UserAssist/ShimCache when standard artifacts are wiped.
- Python installer at `Z:\\setups\\python-3.8.2.exe` = evidence of tool staging from external/network drive.
- `SYSTEM\\CurrentControlSet\\Enum\\USBSTOR` + `Windows Portable Devices` → full USB forensics: FriendlyName **USB**, last connected **2021-11-24 18:40:06**.
- Safe VM + live hives = full registry forensics without rebooting or imaging the suspect machine.

# Socials

**Repository:** https://github.com/RahulCyberX/Digital-Forensics-Incident-Response

**Medium Article:** https://medium.com/@rahulcyberx/windows-forensics-1-complete-tryhackme-walkthrough-fea95d679f5c?source=your_stories_outbox---writer_outbox_published-----------------------------------------

**TryHackMe Profile:** https://tryhackme.com/p/0xRahuL

**Github Profile:** https://github.com/RahulCyberX