# OsQuery SQL-Based Endpoint Interrogation

# Objectives

- Applied Osquery SQL queries inside TryHackMe’s isolated Windows VM to hunt real forensic evidence across the entire system.
- Discovered wipedisk tools via the **userassist** table, identified installed VPN software, counted live services, and exposed auto-starting batch files hidden in startup folders.
- Proved Osquery turns a live endpoint into a searchable database—no agents, no reboots, just pure SQL in a safe sandbox.
- VM: https://tryhackme.com/room/osqueryf8

# Tools Used

- **Osquery** (interactive shell, .tables, SELECT * FROM ...)
- **SQL filters** (LIKE '%VPN%', LIKE '%.bat', COUNT(*))
- **Osquery schema docs**
- **Built-in tables** (userassist, programs, services, autoexec)

# Investigation

## Step 1: Identify Which Table Stores Process Execution Evidence in Windows

To start, I needed to find which table stores evidence of process execution in Windows OS.

I used the `.tables` command to view all available tables:

```bash
.tables
```

However, to be sure, I checked the official Osquery documentation for Windows:

👉 [https://osquery.io/schema/5.5.1](https://osquery.io/schema/5.5.1)

After some exploration and testing, I found that the correct table is **userassist**.

**About userassist table:**

![image.png](image.png)

- It tracks when a user executes an application from Windows Explorer.
- It logs execution path, timestamp, execution count, and user SID.

**Schema columns:**

- `path` → Application file path
- `last_execution_time` → Timestamp of last execution
- `count` → Number of times executed
- `sid` → Security Identifier (User SID)

---

## Step 2: Find the Program Executed to Remove Disk Traces

I used the **userassist** table found in the previous step.

To view all entries and check for any suspicious programs, I ran:

```sql
SELECT * FROM userassist;
```

After carefully examining the results, I noticed one entry for **DiskWipe.exe** — a program known to remove or wipe disk traces.

![image.png](image%201.png)

---

## Step 3: Identify VPN Installed on the Host

Next, I had to identify which VPN software is installed.

For this, I used the **programs** table, which lists all installed programs.

I filtered for names containing “VPN” using the `LIKE` operator:

```sql
SELECT * FROM programs WHERE name LIKE '%VPN%';
```

From the results, I found an entry for **ProtonVPN**.

![image.png](image%202.png)

---

## Step 4: Count Running Services

To determine how many services were currently running on the host, I queried the **services** table.

I used the `COUNT(*)` function to count the number of entries:

```sql
SELECT COUNT(*) FROM services;

```

The total count returned was **215**.

![image.png](image%203.png)

---

## Step 5: Identify Batch File That Runs Automatically

The next step was to find which batch file (`.bat`) runs automatically when the machine starts.

The **autoexec** table stores executables configured to auto-run.

I searched for entries ending with `.bat` using:

```sql
SELECT * FROM autoexec WHERE name LIKE '%.bat';
```

This revealed one batch file named **batstartup.bat**.

![image.png](image%204.png)

---

## Step 6: Find the Full Path of the Batch File

Finally, I needed to find the full path of that same `.bat` file from the **autoexec** table.

I found the complete path by checking the path column of the previous query:

**Answer:**

`C:\Users\James\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\batstartup.bat`

---

# Lessons Learned

- .tables + schema docs = instant map of every forensic goldmine on Windows.
- userassist catches GUI-launched malware (DiskWipe.exe) that Process Creation might miss.
- LIKE '%keyword%' on programs table finds hidden VPNs in seconds.
- COUNT(*) from services = one-liner health check on any endpoint.
- autoexec + LIKE '%.bat' exposes startup persistence attackers love.
- Safe VM + Osquery = I just DFIR’d a live box with nothing but SQL.

# Socials

**Repository:** https://github.com/RahulCyberX/Endpoint-Security-Monitoring

**Medium Article:** https://medium.com/@rahulcyberx/osquery-the-basics-endpoint-security-monitoring-thm-2025-5ff1f6da76b7?source=your_stories_outbox---writer_outbox_published-----------------------------------------

**TryHackMe Profile:** https://tryhackme.com/p/0xRahuL

**Github Profile:** https://github.com/RahulCyberX