# Linux Forensics – System Enumeration, Execution Evidence & Log Analysis

## Objectives

- Enumerate Linux OS, users, groups, sudo policy, and login history directly from filesystem artifacts.
- Identify system configuration (hostname, timezone, interfaces, DNS) and live network activity.
- Locate common persistence mechanisms (cron, init scripts, shell startup files) and confirm settings.
- Extract evidence of execution from auth logs, bash history, and editor traces.
- Inspect system and application logs under `/var/log/` and recover historical context (e.g., prior hostname).

### Tools Used

- VM: [https://tryhackme.com/room/linuxforensics](https://tryhackme.com/room/linuxforensics)
- **Core utilities:** `cat`, `grep`, `column`, `tail`, `head`, `more`, `less`, `gzip -d`
- **Account/identity artifacts:**
    - `/etc/os-release` (distro/version)
    - `/etc/passwd`, `/etc/shadow` (users), `/etc/group` (groups)
    - `/etc/sudoers` (sudo policy)
- **Auth & session history:**
    - `last -f /var/log/wtmp` (logins)
    - `/var/log/btmp` (failed), `/var/log/auth.log*` (sudo, auth events)
- **System configuration:**
    - `/etc/hostname`, `/etc/timezone`
    - `/etc/network/interfaces`, `ip address show`
    - `netstat -natp`, `ps aux | grep <proc>`
    - `/etc/hosts`, `/etc/resolv.conf`
- **Persistence locations:**
    - `/etc/crontab` (scheduled tasks)
    - `/etc/init.d/` (legacy services)
    - `~/.bashrc`, `/etc/bash.bashrc`, `/etc/profile` (shell startup)
- **Execution traces:**
    - `/home/<user>/.bash_history`
    - `~/.viminfo` (recent files, searches)
- **Application logs:** `/var/log/apache2/`, `/var/log/samba/`, `/var/log/mysql/`

# Investigation

## Task 1: Introduction

In this room, I started learning about **forensics on Linux systems** — an essential skill since Linux is widely used in **servers** and sometimes in **enterprise endpoints**.

### Learning Objectives

- Understand Linux and its distributions.
- Gather OS, account, and system info from a Linux machine.
- Find running, executed, and scheduled processes.
- Analyze Linux log files.
- Identify common third-party applications and their logs.

---

## Task 2: Linux Forensics

Linux is **open-source, lightweight, modular**, and **customizable**, which makes it ideal for servers, IoT devices, and even smartphones.

![0_nNUVyylH5bnFvudW.webp](0_nNUVyylH5bnFvudW.webp)

Some common **Linux distributions (distros)** include:

- Ubuntu
- Redhat
- ArchLinux
- OpenSUSE
- Linux Mint
- CentOS
- Debian

For this room, I used **Ubuntu**.

---

## Task 3: OS and Account Information

Just like the **Windows Registry** stores important info, in Linux **everything is stored in files**.

I used the following tools to gather information.

### Access Credentials for VM

```
Username: ubuntu
Password: 123456
```

### A. OS Release Info

To find the OS release information, I use the `cat` utility to read the file located at `/etc/os-release`.

To know more about the `cat` utility, we can read its man page.

`man cat`

Command to get OS release info:

```bash
cat /etc/os-release
```

![image.png](image.png)

### B. User Accounts

Command:

```bash
cat /etc/passwd | column -t -s :
```

- The `/etc/passwd` file lists all user accounts.
    
    ![image.png](image%201.png)
    
    Now I can see information for the user ubuntu. 
    
    The username is ubuntu, its password information field shows x, which signifies that the password information is stored in the /etc/shadow file. 
    
    The uid of the user is 1000. The gid is also 1000. 
    
    The description, which often contains the full name or contact information, mentions the name Ubuntu. 
    
    The home directory is set to /home/ubuntu, and the default shell is set to /bin/bash. 
    
    We can see similar information about other users from the file as well.
    
    - The user “ubuntu” has:
        - `uid=1000`, `gid=1000`
        - Home directory: `/home/ubuntu`
        - Shell: `/bin/bash`
        - Password info stored in `/etc/shadow`

### C. Group Information

```bash
cat /etc/group
```

![1_SVTaK7RHtSKZlyhKjOexpw.webp](1_SVTaK7RHtSKZlyhKjOexpw.webp)

- Shows all groups and which users belong to them.
- Example: `ubuntu` is in the **adm** group.

### D. Sudoers List

A Linux host allows only those users to elevate privileges to `sudo`, which are present in the Sudoers list.

Command:

```bash
sudo cat /etc/sudoers
```

![1_bdA2frvCi34nryEu99fmxA.webp](1_bdA2frvCi34nryEu99fmxA.webp)

- Lists users allowed to elevate privileges using **sudo**.

### E. Login Information

These files are not regular text files that can be read using cat, less or vim; instead, they are binary files, which have to be read using the last utility

Files located in `/var/log`:

- **btmp** → failed logins
- **wtmp** → login history

Command:

```bash
last -f /var/log/wtmp
```

![image.png](image%202.png)

### F. Authentication Logs

Every user that authenticates on a Linux host is logged in the auth log

File: `/var/log/auth.log`
It can be read using the `cat` utility, however, given the size of the file, you can use `tail`, `head`, `more` or `less` utilities to make it easier to read.

Command:

```bash
cat /var/log/auth.log | less
```

![1_jBII9BlKBH_Q33J07upj_A.webp](1_jBII9BlKBH_Q33J07upj_A.webp)

- Logs user authentications and sudo usage.

---

### Questions & Answers

**3.1** Which two users are members of the `audio` group?

Per the task, I can find it by reading the /etc/group file, then pipe in ‘audio’:

```bash
cat /etc/group | grep audio
```

![image.png](image%203.png)

**Answer:** `ubuntu,pulse`

**3.2** What is the UID of the user `tryhackme`?

![image.png](image%204.png)

```bash
cat /etc/passwd | grep tryhackme
```

**Answer:** `1001`

**3.3** Session started on Sat Apr 16 20:10 — how long did it last?

```bash
last -f /var/log/wtmp
```

![image.png](image%205.png)

**Answer:** `01:32`

---

## Task 4: System Configuration

### 1. Hostname

File: `/etc/hostname`

```bash
cat /etc/hostname
```

![1_jlp3AgN5pRmZT3nkCSUgLQ.webp](1_jlp3AgN5pRmZT3nkCSUgLQ.webp)

**Answer:** `Linux4n6`

### 2. Timezone

File: `/etc/timezone`

```bash
cat /etc/timezone
```

![1_7Sl4K8eVC7Stn8jQTqXBAQ.webp](1_7Sl4K8eVC7Stn8jQTqXBAQ.webp)

**Answer:** `Asia/Karachi`

### 3. Network Configuration

File: `/etc/network/interfaces`

```bash
cat /etc/network/interfaces
```

![1_ZlUzxMkulZDpUxM6ehXsJA.webp](1_ZlUzxMkulZDpUxM6ehXsJA.webp)

For live systems, to check IPs and interfaces:

```bash
ip address show
```

![1_PUWnGnA1lA8Cf3RzvZgNhw.webp](1_PUWnGnA1lA8Cf3RzvZgNhw.webp)

### 4. Active Network Connections

On a live system, knowing the active network connections provides additional context to the investigation. 

Command:

```bash
netstat -natp
```

- `n` → show numeric addresses
- `a` → show all connections
- `t` → show TCP
- `p` → show program name

![image.png](image%206.png)

**Answer:**

- Program listening on 127.0.0.1:5901 → `Xtigervnc`

### 5. Full Path of Program

Command:

```bash
ps aux | grep Xtigervnc
```

![image.png](image%207.png)

**Answer:** `/usr/bin/Xtigervnc`

### 6. DNS Configuration

- File for hostname resolution: `/etc/hosts`
- File for DNS servers: `/etc/resolv.conf`

```bash
cat /etc/hosts
cat /etc/resolv.conf
```

![1_CmCckScxeX6q2bCuAUDy3w.webp](1_CmCckScxeX6q2bCuAUDy3w.webp)

![1_P2-wF4KZnHLpoOZYb25Bkg.webp](1_P2-wF4KZnHLpoOZYb25Bkg.webp)

---

## Task 5: Persistence Mechanisms

Persistence mechanisms help attackers **retain access** to a Linux system even after a reboot. My goal here was to identify where such persistence methods can be found.

---

### A. Cron Jobs

- **Cron jobs** are commands or scripts that run automatically at scheduled intervals.
- These are defined in the file:
    
    ```
    /etc/crontab
    ```
    
    To view the cron jobs:
    
    ```bash
    cat /etc/crontab
    ```
    
    ![image.png](image%208.png)
    
    - The file contains:
        - The **schedule timing**
        - The **user** executing it
        - The **command** or **script** being run

---

### 2. Service Startup

- Like **Windows services**, Linux services start automatically in the background when the system boots.
- These are stored in:
    
    ```
    /etc/init.d/
    ```
    
    To list them:
    
    ```bash
    ls /etc/init.d
    ```
    
    ![1_iNRVA81vRYnVzxDlIMHyjQ.webp](1_iNRVA81vRYnVzxDlIMHyjQ.webp)
    

---

### 3. .bashrc File

- Each time a **bash shell** is opened, it executes the commands inside `.bashrc`.
- This file is often abused by attackers for persistence.
    
    To view:
    
    ```bash
    cat ~/.bashrc
    ```
    
    ![1_dOLpdYKCPxk7PLHgZD4jTA.webp](1_dOLpdYKCPxk7PLHgZD4jTA.webp)
    
    System-wide startup scripts can also exist in:
    
    - `/etc/bash.bashrc`
    - `/etc/profile`

---

### Question 5.1

**In the bashrc file, what is the size of the history file set for user ubuntu?**

Command:

```bash
cat ~/.bashrc | grep HISTSIZE
```

![1_PfgIdSws5ZeWsT7kO4BF5w.webp](1_PfgIdSws5ZeWsT7kO4BF5w.webp)

**Answer:** `2000`

---

## Task 6: Evidence of Execution

Here, I identified evidence showing which programs were executed on the Linux machine.

Linux keeps execution traces in multiple locations.

---

### 1. Sudo Execution History

All commands run with `sudo` are logged inside the **auth log**:

```
/var/log/auth.log
```

To view only `sudo` commands:

```bash
cat /var/log/auth.log* | grep sudo
```

![1_mhIuRuZ9Req1NKTP0NCTuQ.webp](1_mhIuRuZ9Req1NKTP0NCTuQ.webp)

---

2. Bash History

Each user’s bash command history is stored in their home directory:

```
/home/<username>/.bash_history
```

![1_Q-pC3sKNBT5mOOtLdwZB1A.webp](1_Q-pC3sKNBT5mOOtLdwZB1A.webp)

Examples:

```bash
cat /home/ubuntu/.bash_history
cat /root/.bash_history
```

---

### 3. Files Accessed Using Vim

If any files were opened in the **Vim editor**, information is stored in:

```
~/.viminfo
```

To read it:

```bash
cat ~/.viminfo

```

![1_poB0Dq-cXOF55slrKD9rmQ.webp](1_poB0Dq-cXOF55slrKD9rmQ.webp)

This file may contain:

- Recently opened files
- Search history
- Command-line history

---

### Questions

**6.1** The user *tryhackme* used `apt-get` to install a package. What was the command?

```bash
cat /var/log/auth.log* | grep -i apt-get
```

![1_gaHgCP8XI4--fAdiPpqbVg.webp](1_gaHgCP8XI4--fAdiPpqbVg.webp)

**Answer:** `sudo apt-get install apache2`

---

**6.2** What was the current working directory when the command to install net-tools was issued?

Using the same command as previous one

![1_2ajwsJFLx9AK7cxunyNNJA.webp](1_2ajwsJFLx9AK7cxunyNNJA.webp)

**Answer:** `/home/ubuntu`

---

## Task 7: Log Files

Log files are one of the **most valuable forensic artifacts** in Linux.

They contain detailed historical records of system and user activity.

Almost all logs are stored in:

```
/var/log/
```

---

### A.  Syslog

- Main system activity log.
- Since the Syslog is a huge file, it is easier to use `tail`, `head`, `more` or `less` utilities to help make it more readable.
- Found at:
    
    ```
    /var/log/syslog
    ```
    
- Older rotated logs are named:
    
    ```
    syslog.1, syslog.2.gz, syslog.3.gz, ...
    ```
    
- View logs:
    
    ```bash
    cat /var/log/syslog* | head
    ```
    
    ![1_BrGpOmYYbXLnvJeZjXIuBQ.webp](1_BrGpOmYYbXLnvJeZjXIuBQ.webp)
    
- To view all rotated logs at once:
    
    ```bash
    cat /var/log/syslog* | grep <keyword>
    ```
    

---

### B. Auth Logs

- Located at:
    
    ```
    /var/log/auth.log
    ```
    
- Contains:
    - User authentications
    - Privilege escalations
    - Group/user creation events
    
    To view:
    
    ```bash
    cat /var/log/auth.log* | head
    ```
    
    ![1_ABMxEg5jLQPvOblI5gCeYw.webp](1_ABMxEg5jLQPvOblI5gCeYw.webp)
    

---

### C. Third-Party Application Logs

Many third-party tools (like web servers or databases) store their logs inside `/var/log/` directories. Examples:

| Application | Log Directory |
| --- | --- |
| Apache Web Server | `/var/log/apache2/` |
| Samba (File Sharing) | `/var/log/samba/` |
| MySQL Database | `/var/log/mysql/` |

To explore:

```bash
ls /var/log/
```

[https://www.notion.so](https://www.notion.so)

As is obvious, we can find the apache logs in the apache2 directory and samba logs in the samba directory.

![1_mieY0XRk1X-vw-4ZQXJzpA.webp](1_mieY0XRk1X-vw-4ZQXJzpA.webp)

---

### Question 7.1

**What was the previous hostname of the machine?**

Steps:

1. Go to the `/var/log` directory.
    
    ![image.png](image%209.png)
    
2. Unzip the old syslog file:
    
    ```bash
    gzip -d syslog.2.gz
    ```
    
3. Now read the file and pipe hostname into it:
    
    ```bash
    cat syslog.2 | grep hostname
    ```
    
    ![image.png](image%2010.png)
    
    **Answer:** `tryhackme`
    

---

# Lessons Learned

- Linux “everything is a file” makes static forensics straightforward: critical identity and config data live in plaintext under `/etc/`.
- `/etc/passwd` + `/etc/group` quickly ties users to groups (e.g., `audio: ubuntu,pulse`); UIDs confirm identity (`tryhackme` → `1001`).
- `wtmp` with `last` reconstructs sessions precisely (e.g., Sat Apr 16 20:10 lasted `01:32`).
- Host context resolves fast from `/etc/hostname` (`Linux4n6`) and `/etc/timezone` (`Asia/Karachi`).
- Network triage pairs files and live state: `netstat -natp` + `ps` validates listeners and binaries (e.g., `127.0.0.1:5901` by `Xtigervnc`, path `/usr/bin/Xtigervnc`).
- Persistence checks must include `crontab`, init scripts, and shell RC files; `.bashrc` values like `HISTSIZE=2000` affect evidence retention.
- `auth.log*` provides high-fidelity command provenance for privileged actions (e.g., `sudo apt-get install apache2`), while `bash_history` and `~/.viminfo` fill gaps for unprivileged execution and file access.
- Historical system state often hides in rotated logs; decompressing `syslog.2.gz` surfaced the previous hostname (`tryhackme`).
- Application-specific logs under `/var/log/` (Apache/Samba/MySQL) extend visibility beyond the OS into service activity, aiding full-stack incident reconstruction.

# Socials

**Repository:** https://github.com/RahulCyberX/Digital-Forensics-Incident-Response

**Medium Article:** https://medium.com/@rahulcyberx/linux-forensics-complete-tryhackme-walkthrough-7bc7caebb6bb?source=your_stories_outbox---writer_outbox_published-----------------------------------------

**TryHackMe Profile:** https://tryhackme.com/p/0xRahuL

**Github Profile:** https://github.com/RahulCyberX