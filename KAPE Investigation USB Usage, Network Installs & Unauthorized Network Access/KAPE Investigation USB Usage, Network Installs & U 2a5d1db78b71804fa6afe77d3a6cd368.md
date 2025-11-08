# KAPE Investigation: USB Usage, Network Installs & Unauthorized Network Access

## Objectives

- Triage a workstation with **KAPE** and review artefacts in **EZViewer** to validate AUP violations.
- Confirm **USB mass-storage usage**, **software installations from network shares**, and **connections to unknown networks**.
- Correlate artefacts across **USBSTOR, RecentApps, WordWheelQuery, KnownNetworks,** and **Jump Lists** to build a clear activity trail.

## Tools Used

- VM: [https://tryhackme.com/room/kape](https://tryhackme.com/room/kape)
- **KAPE** (Targets/Modules from Task 5) → Registry artefact collection to CSV.
- **EZViewer** for CSV review and filtering.
- **Registry/OS artefacts reviewed:**
    - `USBSTOR.csv` (USB device serials)
    - `RecentApps.csv` (install/execution source & time)
    - `WordWheelQuery.csv` (Windows Search history)
    - `KnownNetworks.csv` (network SSIDs, first-connected timestamps)
    - `AutomaticDestinations.csv` (Jump Lists → file/folder access, source drives)

---

# Investigation

### **Step 1: Run KAPE**

1. Go to the **KAPE directory** on the Desktop in the attached VM.
2. Open **GKAPE** (the GUI version) or use CLI if preferred.
    
    ![image.png](image.png)
    
3. Set the same **Target** and **Module** options as done in *Task 5*.
    
    ![image.png](image%201.png)
    
4. Run the collection and processing task.
    
    ![image.png](image%202.png)
    
    ![image.png](image%203.png)
    
5. Once it finishes, go to the **output folder** → **Registry folder** → open the subfolder created under it.

---

### **Step 2: Find USB Devices (Question 7.1)**

1. Open **USBSTOR.csv** inside the Registry folder using **EZViewer** (from the EZtools folder).
    
    ![image.png](image%204.png)
    
2. You’ll see two registry entries showing USB device details.
    
    ![image.png](image%205.png)
    
3. One is `0123456789ABCDE` (already known).
4. The **other USB’s serial number** listed is:
    
    **Answer:** `1C6F654E59A3B0C179D366AE`
    

---

### **Step 3: Check Software Installation Source (Question 7.2)**

1. In the same Registry folder, open **RecentApps.csv** using EZViewer.
    
    ![image.png](image%206.png)
    
2. Look for entries where software like **7zip, Google Chrome, and Mozilla Firefox** were installed.
    
    ![image.png](image%207.png)
    
3. The drive letter and directory are shown as:
    
    **Answer:** `Z:\setups`
    

---

### **Step 4: Verify Execution Date of CHROMESETUP.EXE (Question 7.3)**

1. Still in **RecentApps.csv**, find the entry for **CHROMESETUP.EXE**.
2. The timestamp column gives the execution date and time.
    
    ![image.png](image%208.png)
    
3. It shows:
    
    **Answer:** `11/25/2021 3:33`
    

---

### **Step 5: Find Search Query Performed on System (Question 7.4)**

1. Open **WordWheelQuery.csv** in the same Registry subfolder.
    
    ![image.png](image%209.png)
    
2. This file contains **Windows Search history**.
3. The recorded query was:
    
    ![image.png](image%2010.png)
    
    **Answer:** `RunWallpaperSetup.cmd`
    

---

### **Step 6: Check Network Connection Time (Question 7.5)**

1. Open **KnownNetworks.csv** in the same Registry subfolder.
    
    ![image.png](image%2011.png)
    
2. This file lists Wi-Fi or LAN networks previously connected.
3. Locate the network named **Network 3**.
4. The “FirstConnected” column shows:
    
    ![image.png](image%2012.png)
    
    **Answer:** `11/30/2021 15:44`
    

---

### **Step 7: Find the Drive Letter of KAPE’s Source (Question 7.6)**

1. Open the **AutomaticDestinations.csv** file from ‘FireFolderAccess” folder.
    
    ![image.png](image%2013.png)
    
2. Search for any entry showing **KAPE** being accessed or copied.
3. It indicates that KAPE was copied from drive:
    
    ![image.png](image%2014.png)
    
    **Answer:** `E:`
    

---

---

### Summary

By analyzing registry artifacts collected through **KAPE** and reviewing them in **EZViewer**, I confirmed multiple Acceptable Use Policy violations:

- User connected **two USB drives** (one Kingston).
- Installed apps from a **network drive (Z:\setups)**.
- Connected to an **unauthorized network (Network 3)**.
- Searched for and executed suspicious commands (`RunWallpaperSetup.cmd`).

These findings clearly demonstrate that the user violated the organization’s policy.

---

# Lessons Learned

- **USB activity** is quickly provable via `USBSTOR.csv` (e.g., serial `1C6F654E59A3B0C179D366AE`).
- **Network-share installs** surface in `RecentApps.csv` with precise paths (e.g., `Z:\setups`) and timestamps (e.g., `CHROMESETUP.EXE` on `11/25/2021 3:33`).
- **Unknown network use** is confirmed via `KnownNetworks.csv` with first-connect times (e.g., **Network 3** on `11/30/2021 15:44`).
- **User intent/actions** appear in `WordWheelQuery.csv` (e.g., `RunWallpaperSetup.cmd`) and are contextually supported by Jump Lists (`AutomaticDestinations.csv`, KAPE sourced from `E:`).
- Cross-artefact correlation from KAPE outputs provides a defensible, end-to-end activity narrative without full disk imaging.

# Socials

**Repository:** https://github.com/RahulCyberX/Digital-Forensics-Incident-Response

**Medium Article:** https://medium.com/@rahulcyberx/kape-complete-tryhackme-walkthrough-894ef4286465?source=your_stories_outbox---writer_outbox_published-----------------------------------------

**TryHackMe Profile:** https://tryhackme.com/p/0xRahuL

**Github Profile:** https://github.com/RahulCyberX