# ELK Stack Incident Investigation – C2 Beaconing

## **Objectives**

* Investigate March 2022 HTTP connection logs in Kibana to confirm suspected **C2 beaconing** by HR employee **Browne**.
* Identify Browne’s source IP, suspicious download activity, and the binary used to contact external servers.
* Correlate HTTP GET requests, user_agent strings, and destination domains to reconstruct the infection chain.
* Discover the full C2 URL on Pastebin and extract the hidden THM flag from the attacker’s file.
* Demonstrate how Kibana Discover + KQL can expose an entire C2 operation from a single log entry inside a safe TryHackMe lab.

---

## **Tools Used**
- VM: [https://tryhackme.com/room/itsybitsy](https://tryhackme.com/room/itsybitsy)
* **Kibana Discover** (March 2022 time filter, Top Values for source_ip, field inspection)
* **KQL filters** (`method : GET` AND `source_ip : 192.166.65.54`)
* **User_Agent Analysis** (bitsadmin → LOLBIN indicator)
* **Pastebin Inspection** (view raw C2 URL and retrieve payload)
* **Browser verification** (for secret.txt content and flag confirmation)

---

# Kibana C2 Investigation

## Scenario Overview

During normal SOC monitoring, analyst **John** observed a suspicious alert in the IDS indicating possible **Command and Control (C2)** communication from a user named **Browne** (HR department).

The suspicious file contained a malicious pattern **THM:{ ________ }**.

A week’s worth of **HTTP connection logs** were pulled and ingested into the **connection_logs** index in **Kibana** for analysis.

My objective was to investigate Browne’s activity, identify the C2 connection, and extract the hidden flag from the malicious file.

---

## Step-by-Step Investigation

### **Step 1: Checking Total Events (March 2022)**

1. Opened **Kibana → Discover**.
    
    ![1_LcbUFvK_FzWO8Tt8AhL3aA.webp](1_LcbUFvK_FzWO8Tt8AhL3aA.webp)
    
2. Adjusted the **date filter** (top-right) to cover **March 2022**.
    
    ![1_GUPUT2Xx_XtlMfGAhVZ56w.webp](1_GUPUT2Xx_XtlMfGAhVZ56w.webp)
    
3. Clicked **Update** to refresh results.
    
    ![1_tLhT920I4JoG_JYZfBlXUQ.webp](1_tLhT920I4JoG_JYZfBlXUQ.webp)
    

---

### **Step 2: Finding Browne’s Source IP**

1. In the **Discover** panel, expanded the left sidebar fields.
2. Clicked on **source_ip** to list all IP addresses.
    
    ![1_GWrc03VTTMj7BiXpy1Lmmg.webp](1_GWrc03VTTMj7BiXpy1Lmmg.webp)
    
3. Compared the hit counts for each and identified Browne’s activity source.

**Answer:** `192.166.65.54`

---

### **Step 3: Identifying the Binary Used for Download**

1. Filtered logs by **method: GET** and the **suspect’s IP**.
    
    ![1_Rb8Adcb5c_AeL7O56uDEfQ.webp](1_Rb8Adcb5c_AeL7O56uDEfQ.webp)
    
2. Found only one related event.
3. Inspected the **user_agent** field — it showed **bitsadmin**, a legitimate Windows binary used for background file transfers.

**Answer:** `bitsadmin`

---

### **Step 4: Finding the C2 Communication Site**

1. Reviewed the same filtered result from the previous step.
2. Observed that the destination domain was a well-known file-sharing site — **Pastebin**, often abused by attackers for C2 communication.
    
    ![1_ZEipyJdPCITHwgJlUjvpog.webp](1_ZEipyJdPCITHwgJlUjvpog.webp)
    

---

### **Step 5: Determining the Full C2 URL**

1. In the same log, located the **URI** path accessed by the infected host.
    
    ![1_vUaycKXQ7zXUDLZZu7cTbQ.webp](1_vUaycKXQ7zXUDLZZu7cTbQ.webp)
    
2. Combined the **domain + URI** to form the complete C2 URL.

**Answer:** `pastebin.com/yTg0Ah6a`

---

### **Step 6: Finding the File Accessed**

1. Opened the full C2 link in a browser.
2. Observed the file hosted on Pastebin.
    
    ![1_85fhLxe_IEXskjRM_3wu3Q.webp](1_85fhLxe_IEXskjRM_3wu3Q.webp)
    
3. Found the name of the file which was accessed on the file sharing site.

---

### **Step 7: Extracting the Hidden Code**

1. Viewed the **content** of `secret.txt` directly on Pastebin.
2. Found the hidden malicious string in the format `THM{_____}`.

---


## **Findings**

* **Source IP:** `192.166.65.54` belonged to Browne’s system.
* **User Agent:** `bitsadmin` — a legitimate Windows utility abused for file transfers.
* **C2 Domain:** `pastebin.com` used for exfiltration and command retrieval.
* **C2 URL:** `pastebin.com/yTg0Ah6a`
* **Downloaded File:** `secret.txt` hosted on Pastebin.
* **Recovered Flag:** `THM{...}` inside Pastebin’s raw content.

---

## **Lessons Learned**

* Start with Top Values for **source_ip** to isolate the noisiest host fast.
* **bitsadmin** in logs is a classic LOLBIN beacon—no custom malware needed.
* A single **KQL** filter (`method:GET AND source_ip`) cuts straight to the infection chain.
* Pastebin is a common C2 medium—always inspect URI paths and raw data.
* Elastic Stack logs + Kibana UI = complete C2 forensics from a browser with zero endpoint access.



# Socials

**Repository:** https://github.com/RahulCyberX/Security-Information-Event-Management

**Medium Article:** https://medium.com/@rahulcyberx/itsybitsy-complete-tryhackme-walkthrough-2bd024c87da2?source=your_stories_outbox---writer_outbox_published-----------------------------------------

**TryHackMe Profile:** https://tryhackme.com/p/0xRahuL

**Github Profile:** https://github.com/RahulCyberX
