# Splunk Anomaly Detection: Detecting Backdoors, Persistence & PowerShell C2

## Objectives

- Dive into **12,256 ingested Windows events** in Splunk’s index="main" to uncover a stealthy backdoor campaign inside a compromised enterprise.
- Hunt for unauthorized user creation, registry persistence, remote execution vectors, and zero interactive logons to prove full automation.
- Track malicious PowerShell activity across the environment, extract encoded payloads, and reveal the hidden C2 callback domain.
- Deliver a complete incident timeline with attacker TTPs, compromised hosts, and network beacons — all using only Splunk SPL and built-in Windows logging in a safe, isolated lab.

## Tools Used

- VM: [https://tryhackme.com/room/investigatingwithsplunk](https://tryhackme.com/room/investigatingwithsplunk)
- **Splunk** (`index="main", EventID=4720/13/1/4688/4624/4625/4104/4103, rex, dedup, table`)
- **Windows Event IDs**
    - 4720 → user creation
    - 13 → registry value set
    - 1/4688 → process creation
    - 4624/4625 → logon success/failure
    - 4104/4103 → PowerShell ScriptBlock + Module logging
- **CyberChef** (Base64 → UTF-16LE decode)

# Investigation

**Goal:** Examine ingested Windows logs in `index="main"` to find anomalies, identify a backdoor user, and trace associated activity (registry changes, remote creation, PowerShell execution, and network callbacks).

---

## Step 0 — Confirm data ingestion

**Why:** Verify logs are available before starting investigation.

**Query I ran:**

```
index="main"
```

**Observation / Answer:**

![image.png](image.png)

I confirmed **12,256** events were collected and ingested in the `main` index.

**Answer:** `12256`

---

## Step 1 — Find new user account creation

**Why:** User account creation on endpoints is a strong indicator of persistence/backdoor activity.

**Query I ran:**

```
index="main" EventID="4720"
```

**Observation:**

![image.png](image%201.png)

Event ID 4720 (user account created) returned a user creation event.

**Answer (new username):** `A1berto`

---

## Step 2 — Locate registry change for the backdoor account

**Why:** Malware/backdoors often add registry entries; mapping the key gives persistence context.

**Query I ran:**

```
index="main" EventID=13 A1berto
```

**Observation:**

![image.png](image%202.png)

I clicked the `TargetObject` field for the EventID=13 result and found the registry path that was updated for the new user.

![0_kfFr-W_yqllos8z7.webp](0_kfFr-W_yqllos8z7.webp)

**Answer (full registry path):** `HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto`

---

## Step 3 — Determine impersonation target

**Why:** Attackers often create usernames similar to legitimate users to evade detection.

**Query I ran:**

```
index="main"
```

**Observation:**

I examined the `User` field values and noted the created account `A1berto` is not the same as `Alberto` — the adversary attempted to impersonate `Alberto`.

![0_jaP_oTaDS18nhfpo.webp](0_jaP_oTaDS18nhfpo.webp)

**Answer (impersonated user):** `Alberto`

---

## Step 4 — Identify the remote command used to add the backdoor user

**Why:** Understanding the exact command shows the attacker’s remote execution vector.

**Query I ran (filtered 4688/1 events and inspected CommandLine):**

Filter events with ID of 4688 of Sysmon event ID of 1. (Both are process creation ID)

```
index="main" EventID=1 OR EventID=4688 A1berto
```

**Observation:**

From the `CommandLine` field I found a WMIC remote execution command that created the new user.

![0_KOV7uDysNN1soiyw.webp](0_KOV7uDysNN1soiyw.webp)

**Answer (command used):**

`C:\windows\System32\Wbem\WMIC.exe” /node:WORKSTATION6 process call create “net user /add A1berto paw0rd1`

---

## Step 5 — Check for backdoor user login attempts

**Why:** If the backdoor was used interactively, there should be successful/failed logons (4624/4625).

**Query I ran:**

```
index="main" EventID="4625" OR EventID="4624" A1berto
```

**EventID** = 4624 (Account successfully logged in)

**EventID** = 4625 (Account failed to log in)

**Observation / Answer:**

![0_r06MIe6JrEba33m5.webp](0_r06MIe6JrEba33m5.webp)

No login attempts by the backdoor user were observed during the investigation.

**Answer:** `0`

---

## Step 6 — Identify host with suspicious PowerShell activity

**Why:** Malicious PowerShell execution often indicates post-exploitation behavior and callbacks.

**Query I ran:**

The following query filters Powershell events.

```
index="main" EventID="4104" OR EventID="4103"
```

![0_Xl09v3EaPti-jQX9.webp](0_Xl09v3EaPti-jQX9.webp)

**Observation:**

PowerShell logging (EventID 4104/4103) returned events from a single host.

![0_ozOM4a_ftyHzlB9d.webp](0_ozOM4a_ftyHzlB9d.webp)

**Answer (infected host):** `James.browne`

---

## Step 7 — Count PowerShell events for the malicious execution

**Why:** Volume of PowerShell events helps scope the activity.

**Query I ran:** (same PowerShell query as above)

```
index="main" EventID="4104" OR EventID="4103”
```

**Observation / Answer:**

![0_QflGcOLrvx542ih7.webp](0_QflGcOLrvx542ih7.webp)

I observed **79** PowerShell events related to the malicious execution.

**Answer:** `79`

---

## Step 8 — Extract encoded PowerShell payload and find the callback URL

**Why:** Encoded PowerShell often contains network I/O (web requests) — extracting it can reveal C2 or payload hosts.

**Query I ran to extract the host application value (deduplicated):**

```
index="main" EventID="4104" OR EventID="4103"
| rex field=ContextInfo "Host Application = (?<Command>[^\r\n]+)"
| table Command
| dedup Command
```

This modified query will extract the value of “Host Application” from the field “ContextInfo”, present it on a table without duplicate command

**Observation:**

The `Command` value was base64-encoded. 

![0_tK3Kp2K2GUFAFJlr.webp](0_tK3Kp2K2GUFAFJlr.webp)

I copied the encoded value, decoded it externally (CyberChef), and found a web request to a PHP resource.

![0_1ytnD3y9gO6XKZ6G.webp](0_1ytnD3y9gO6XKZ6G.webp)

**Answer (full URL observed):** `hxxp[://]10[.]10[.]10[.]5/news[.]php`

---

# Lessons Learned

- `EventID=4720` instantly flags backdoor accounts — `A1berto` vs `Alberto` = textbook typo-squatting.
- `EventID=13` + username → full registry persistence path in one search.
- `EventID=4688 OR 1` + username → exposes WMIC remote user creation in a single line.
- Zero `4624/4625` events for the backdoor = pure automation, no interactive session needed.
- `EventID=4104 OR 4103` → 79 malicious PowerShell blocks isolated to host `James.browne`.
- `rex "Host Application = (?<Command>[^\\r\\n]+)"` + `dedup` = surgical extraction of encoded commands.
- Base64 → UTF-16LE decode reveals final C2 beacon: `hxxp://10.10.10.5/news.php`.
- Safe VM + pre-ingested `main` index = full enterprise breach investigation using nothing but Splunk and 8 queries.

# Socials

**Repository:** https://github.com/RahulCyberX/Security-Information-Event-Management

**Medium Article:** https://rahulcyberx.medium.com/investigating-with-splunk-complete-tryhackme-walkthrough-18bdcf10b18a

**TryHackMe Profile:** https://tryhackme.com/p/0xRahuL

**Github Profile:** https://github.com/RahulCyberX