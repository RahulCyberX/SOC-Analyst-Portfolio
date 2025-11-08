# Critical Infrastructure Memory Forensics with Volatility

## Objectives

- Analyze `memdump.mem` to confirm ransomware-like activity affecting `important_document.pdf`.
- Identify suspicious processes, network connections, file paths, and timestamps.
- Extract in-memory artifacts (URLs/keys/headers) that indicate the actor and tooling.

## Tools Used

- VM: [https://tryhackme.com/room/critical](https://tryhackme.com/room/critical)
- **Volatility 3**: `windows.info`, `windows.pstree`, `windows.netscan`, `windows.netstat`, `windows.filescan`, `windows.mftscan.MFTScan`, `windows.memmap --dump`.
- **CLI helpers**: `strings`, `grep`, `less`.
- **Acquisition reference**: FTK Imager (source of the dump).

---

# [Investigation]

## Incident Scenario

I’m joining the DFIR team because our user **Hattori** reported strange behavior: several **PDF files were encrypted**, including a critical company file `important_document.pdf`. Credentials may have been stolen, so the team captured evidence and asked me to investigate a **memory dump** from the compromised Windows machine to find useful artifacts and identify possible malicious actors.

![image.png](image.png)

# Learning Objectives

I will complete the room and cover these objectives:

- Understand **basic concepts of memory forensics**.
- **Set up and access** the forensic environment.
- **Gather information** from the compromised Windows target.
- **Search for suspicious activity** using gathered info.
- **Extract and analyse data** from memory (artifacts that point to malicious actors).
- Summarize **conclusions & further steps** after finishing the investigation.

# Task 2: Memory Forensics

## What is Memory Forensics

Memory forensics is a **subset of computer forensics** focused on analyzing **volatile memory (RAM)** from a compromised machine.

- In **Windows OS**, this means analyzing the system’s **RAM**, which gets **wiped on reboot or shutdown**.
- It’s one of the **first steps** in an incident response, as evidence can disappear quickly.

Unlike **disk forensics**, which looks at stored files, **memory forensics** reveals:

- **Running processes and applications** at the time of capture.
- **Execution flow** and in-memory data not saved on disk.
- **Real-time attacker activity** that might not exist in logs or storage.

![image.png](image%201.png)

## Why It’s Important

Memory analysis gives an **immediate snapshot** of what was happening on the system — helping reconstruct the **timeline of an attack** and identify actions taken by the attacker.

It’s invaluable for building a **chronology of events** and proving how a compromise occurred.

## Two Main Phases of Memory Forensics

### 1. **Memory Acquisition**

- Capture (copy) the **live system memory** to a file — called a **memory dump**.
- Done to preserve volatile data safely for offline analysis.
- Prevents data loss in case the system reboots.
- Serves as **evidence** for investigation or legal needs.

*(Think of it as “taking a photo” of the system’s RAM.)*

### 2. **Memory Analysis**

- Investigate the **memory dump** to uncover forensic data.
- Look for malicious processes, injected code, stolen credentials, or traces of attacker activity.

**What type of memory is analyzed during a forensic memory task?**

Answer: **`RAM`**

**In which phase will you create a memory dump of the target system?**

Answer: **`Memory Acquisition`**

# Task 3: Environment & Setup

I will perform **memory acquisition** and prepare the analysis environment. The lab used an **FTK Imager**-created memory dump (`memdump.mem`) copied to a Linux analyst VM. I’ll use **Volatility 3** (aliased as `vol`) to analyse the dump.

---

## Imaging tools (by OS)

- **Windows:** FTK Imager, WinPmem
- **Linux:** LIME
- **macOS:** osxpmem

In this scenario the memory was captured with **FTK Imager** and placed on the Linux analyst machine.

---

## Accessing the VM / evidence

- VM may be started via the lab UI (Start Machine ≈ 2 minutes).
- If hidden, click **Show Split View**.
- Or SSH directly:

```bash
ssh analyst@MACHINE_IP
# password: forensics
```

- Memory dump path:
    
    `/home/analyst/memdump.mem`
    

---

## Tool: Volatility 3 (installed, alias `vol`)

- Run help:

```bash
vol -h
```

![image.png](image%202.png)

- Volatility accepts many options and supports plugins via the syntax:

```bash
vol <os> <plugin> [options] -f /path/to/memdump.mem
```

To list Windows-specific plugins (example):

```bash
vol windows --help
```

```
**user@machine$ vol windows --help
usage: volatility [-h] [-c CONFIG] [--parallelism [{processes,threads,off}]] [-e EXTEND] [-p PLUGIN_DIRS] [-s SYMBOL_DIRS] [-v] [-l LOG] [-o OUTPUT_DIR] [-q] [-r RENDERER] [-f FILE] [--write-config] [--save-config SAVE_CONFIG] [--clear-cache] [--cache-path CACHE_PATH] [--offline]
                  [--single-location SINGLE_LOCATION] [--stackers [STACKERS [STACKERS ...]]] [--single-swap-locations [SINGLE_SWAP_LOCATIONS [SINGLE_SWAP_LOCATIONS ...]]]
                  plugin ...
volatility: error: argument plugin: plugin windows matches multiple plugins (windows.bigpools.BigPools, windows.cachedump.Cachedump, windows.callbacks.Callbacks, windows.cmdline.CmdLine, windows.crashinfo.Crashinfo, windows.devicetree.DeviceTree, windows.dlllist.DllList, windows.driverirp.DriverIrp, windows.drivermodule.DriverModule, windows.driverscan.DriverScan, windows.dumpfiles.DumpFiles, windows.envars.Envars, windows.filescan.FileScan, windows.getservicesids.GetServiceSIDs, windows.getsids.GetSIDs, windows.handles.Handles, windows.hashdump.Hashdump, windows.info.Info, windows.joblinks.JobLinks, windows.ldrmodules.LdrModules, windows.lsadump.Lsadump, windows.malfind.Malfind, windows.mbrscan.MBRScan, windows.memmap.Memmap, windows.mftscan.ADS, windows.mftscan.MFTScan, windows.modscan.ModScan, windows.modules.Modules, windows.mutantscan.MutantScan, windows.netscan.NetScan, windows.netstat.NetStat, windows.poolscanner.PoolScanner, windows.privileges.Privs, windows.pslist.PsList, windows.psscan.PsScan, windows.pstree.PsTree, windows.registry.certificates.Certificates, windows.registry.hivelist.HiveList, windows.registry.hivescan.HiveScan, windows.registry.printkey.PrintKey, windows.registry.userassist.UserAssist, windows.sessions.Sessions, windows.skeleton_key_check.Skeleton_Key_Check, windows.ssdt.SSDT, windows.statistics.Statistics, windows.strings.Strings, windows.svcscan.SvcScan, windows.symlinkscan.SymlinkScan, windows.vadinfo.VadInfo, windows.vadwalk.VadWalk, windows.vadyarascan.VadYaraScan, windows.verinfo.VerInfo, windows.virtmap.VirtMap)**
```

---

Plugins are extremely helpful during the analysis when using Volatility3 since they will quickly parse a memory dump for specific data types and sort the data according to the selected plugin.

## Key Volatility3 Windows plugins (what they return)

- `windows.info` — OS & kernel details for the memory sample.
- `windows.pslist` — processes present at capture (flat list).
- `windows.pstree` — processes as a parent/child tree.
- `windows.cmdline` — process command line arguments.
- `windows.netscan` — network objects (connections/sockets).
- `windows.netstat` — alternate network tracking info.
- `windows.drivermodule` — loaded drivers (detect hidden/rootkit drivers).
- `windows.filescan` — file objects found in memory.
- `windows.dumpfiles` — extract files from memory image.
- `windows.handles` — open handles per process.
- `windows.getsids` — process owner SIDs.
- `windows.mftscan` — scan for NTFS MFT / ADS artifacts.
- `windows.malfind` — detect in-memory code injections / suspicious sections.
- `windows.strings` — search readable strings in memory.
- `windows.lsadump` / `windows.hashdump` — extract credentials / hashes (use carefully, forensically important).

**Which plugin can help us to get information about the OS running on the target machine?**

`windows.info`

**Which tool referenced above can help us take a memory dump on a Linux OS?**

`LIME`

**Which command will display the help menu using Volatility on the target machine?**

`vol -h`

# Task 4: Gathering Target Information

### Obtaining Information

Getting basic details about the target ensures we’re analyzing the right system and context. This helps confirm the OS type, architecture, and environment to make our findings accurate and legitimate.

We use the command:

```bash
vol -f memdump.mem windows.info
```

This Volatility plugin gives general system information from the memory dump.

![image.png](image%203.png)

These details confirm we’re working on the correct compromised Windows system and allow correlation with other analyses or hardware evidence.

**Next step:**

Run `vol -f memdump.mem windows.info` in the working directory to gather this info before proceeding.

### Answer the questions:

I made sure that I am in the correct directory which is `/home/analyst/`

![image.png](image%204.png)

And here’s the memdump file that I need to answer the questions in this room.

I ran this command:

```
vol -f memdump.mem [windows.info](http://windows.info/)
```

`windows.info` = A plugin that gives OS & kernel details for the memory sample.

Scan will take some time, so I went AFK and go annoy my cat for the time being. 

![image.png](image%205.png)

This alone provided all the necessary information needed to complete the answers. 

**Is the architecture of the machine x64 (64bit) Y/N?**

Answer: `Y`

**What is the Verison of the Windows OS**

![image.png](image%206.png)

Answer: `10`

**What is the base address of the kernel?**

![image.png](image%207.png)

Answer: `0xf8066161b000`

# Task 5: Searching for Suspicious Activity

Now that we know the target’s system details, the next step is to identify **suspicious activity** in the memory dump — signs of compromise like **unknown processes, strange network connections, or modified registry entries**.

---

## Network Activity Check

We start by checking active connections using:

```bash
vol -f memdump.mem windows.netstat
```

![image.png](image%208.png)

**Findings:**

- A connection was established on **port 3389** (Remote Desktop Protocol).
- Source: `192.168.182.139`
- Timestamp: `2024-02-24 22:47:52`
    
    This likely indicates **remote access by the attacker** — possibly their initial entry point.
    

---

## Process Analysis

Next, we check running processes in a tree view using:

```bash
vol -f memdump.mem windows.pstree
```

![image.png](image%209.png)

- The output lists processes by **PID (Process ID)** and **PPID (Parent Process ID)**.
- It showed `services.exe` (PID 636) as the **parent process** of `dllhost.exe` (PPID 636), which is normal for Windows.

---

## Detecting Suspicious Processes

![image.png](image%2010.png)

To identify suspicious ones:

- Compare process names against the **default Windows process list**.
- Look for **unfamiliar or truncated names** mimicking system processes.

**Observation:**

![image.png](image%2011.png)

A process named **`critical_updat`** (truncated) was found, acting as the **parent process** of **`updater.exe`**.

- Both are **not standard Windows processes**.
- `critical_updat` → Parent
- `updater.exe` → Child

These are strong indicators of **malicious activity**.

### Answer the questions:

**Using the plugin "windows.netscan". Can you identify the destination IP address where a connection is established on port 80?**

Command I used:

```
vol -f memdump.mem windows.netscan | grep -i ESTABLISHED
```

![image.png](image%2012.png)

Answer: `192.168.182.128`

**Using the plugin "windows.netscan," can you identify the program (owner) used to access through port 80?**

Answer: `msedge.exe`

**Analyzing the processes present on the dump, what is the PID of the child process of critical_updat?**

Command I used:

```
vol -f memdump.mem windows.pstree
```

![image.png](image%2013.png)

Answer: `1612`

**What is the time stamp time for the process with the truncated name critical_updat?**

![image.png](image%2014.png)

Answer: `2024-02-24 22:51:50.000000`

# Task 6: Finding Interesting Data

### Investigating `critical_updat` → `updater.exe`

- I searched file objects in memory to find where `updater.exe` resided:
    
    ```bash
    vol -f memdump.mem windows.filescan > filescan_out
    cat filescan_out | grep updater
    ```
    
    ![image.png](image%2015.png)
    
    → `C:\Users\user01\Documents\updater.exe`
    
- I checked MFT entries to capture file timestamps (Created / Modified / MFT Updated / Accessed):
    
    ```bash
    vol -f memdump.mem windows.mftscan.MFTScan > mftscan_out
    cat mftscan_out | grep updater
    ```
    
    ![image.png](image%2016.png)
    
    → Recorded the four timestamps for `updater.exe`.
    
- I dumped the memory regions for the `updater.exe` process (PID 1612) for deeper inspection:
    
    ```bash
    vol -f memdump.mem -o . windows.memmap --dump --pid 1612
    # produces pid.1612.dmp
    ```
    
- I examined printable strings from the dumped region to find network artifacts and file interactions:
    
    ```bash
    strings pid.1612.dmp | less
    ```
    
    ![image.png](image%2017.png)
    
    → Found URL: `http://key.critical-update.com/encKEY.txt` 
    
    Immediately identified a possible key and a domain from a URL that the process may have accessed. Also, by scrolling down, found more indications that this is a malicious process since we can find the `important_document.pdf` filename indicating an interaction with the file.
    
    ![image.png](image%2018.png)
    
    As I found a reference to `important_document.pdf` inside the process memory, indicating `updater.exe` accessed that file at some point in the URL `http://key.critical-update.com/encKEY.txt` .
    
    ```
    strings pid.1612.dmp | grep -B 10 -A 10 "[http://key.critical-update.com/encKEY.txt](http://key.critical-update.com/encKEY.txt)"
    ```
    
    ![image.png](image%2019.png)
    
- From the above image, we can observe at the end of the HTTP request the content of the file `encKey.txt`, and on the same request, we can observe data with the value `cafebabe`. This could be the key to encrypting the PDF used by the attacker that was not downloaded to disk.
    
    ![image.png](image%2020.png)
    

Excellent. We collected valuable information from the memory dump, including the possible key used to encrypt the documents.

### Answer the questions

**Analyzing the "windows.filescan" output, what is the full path and name for critical_updat?**

Command I ran:

```
vol -f memdump.mem windows.filescan > filescan_out
```

Now to find full path for a file named **critical_update**

```
cat filescan_out | grep critical_update
```

![image.png](image%2021.png)

Answer: `\Users\user01\Documents\critical_update.exe`

**Analyzing the "windows.mftscan.MFTScan" what is the Timestamp for the created date of important_document.pdf?**

First I am gonna save the result as an output because the original output is quite big to look into.

```
**vol -f memdump.mem windows.mftscan.MFTScan > mftscan_out**
```

Now I am gonna read the output and look for the necessary timestamp 

```
cat mftscan_out | grep important_document.pdf
```

![image.png](image%2022.png)

Here, the last four timestamps correspond to the Created, Modified, Updated, and Accessed TImeStamps.

Answer: `2024-02-24 20:39:42.000000`

**Analyzing the updater.exe memory output, can you observe the HTTP request and determine the server used by the attacker?**

```
vol -f memdump.mem -o . windows.memmap --dump --pid 1612
```

Using PID 216 will not give any output because process 216 is not active anymore in memory snapshot. Its a tutorial in an simulated environment so the author picked a process that’s active (so the command produces output) even if the file originally mentioned another PID. 

Anyways, once the memory output is created, you will see that in your directory with a .dmp extension. 

![image.png](image%2023.png)

Now time to navigate through the output, but since examining this file will be difficult because it contains non-printable characters, I am gonna use the strings command, piped to less. 

```
strings pid.1612.dmp |less
```

Now just scroll down while looking for key patterns like `HTTP` or `key` or any pattern that can lead us quickly to an artefact

![image.png](image%2024.png)

So now I have identified a possible key and a domain from a URL that the process may have accessed.

- Key = `encKEY.txt`
- Domain = `http://key.critical-update.com/encKEY.txt`

Now I am gonna use grep command to look for the HTTP request that may be stored in the memory, and use -B and -A to look for 10 lines above and below out match

```
strings pid.1612.dmp |grep -B 10 -A 10 "http://key.critical-update.com/encKEY.txt"
```

![image.png](image%2025.png)

Found the HTTP server, as well as the key “cafebabe” which was probably used to encrypt the PDF by the attacker. 

Answer: `SimpleHTTP/0.6 Python/3.10.4`

---

# Lessons Learned

- Host is **Windows 10 x64**; kernel base `0xf8066161b000`.
- **Suspicious process chain**: `critical_updat` → child **`updater.exe` (PID 1612)**; full path of parent: `\Users\user01\Documents\critical_update.exe`.
- **Network**: RDP seen; HTTP **ESTABLISHED** to **192.168.182.128:80** by **`msedge.exe`**.
- Memory strings from PID 1612 show C2/url **`http://key.critical-update.com/encKEY.txt`**, server header **`SimpleHTTP/0.6 Python/3.10.4`**, and encryption key **`cafebabe`**.
- `important_document.pdf` **Created**: **2024-02-24 20:39:42.000000** (from MFT).
- Workflow takeaway: combine `filescan`/`mftscan` for paths & times, `memmap --dump` + `strings` for in-memory IOCs/credentials to quickly prove impact and actor tooling.

# Socials

**Repository:** https://github.com/RahulCyberX/Digital-Forensics-Incident-Response

**Medium Article:** https://medium.com/@rahulcyberx/critical-complete-tryhackme-walkthrough-15d463b15f9a?source=your_stories_outbox---writer_outbox_published-----------------------------------------

**TryHackMe Profile:** https://tryhackme.com/p/0xRahuL

**Github Profile:** https://github.com/RahulCyberX