# TShark Command-Line Traffic Analysis and Automation

## **Objectives**

* Perform end-to-end packet investigation using **TShark** to uncover phishing and credential theft activity in raw network captures.
* Identify malicious DNS queries, HTTP credential exfiltration, and impersonation domains without relying on any GUI tools.
* Combine **TShark**, **VirusTotal**, and **CyberChef** for rapid indicator extraction, validation, and safe defanging.
* Reconstruct attacker infrastructure from captured DNS, HTTP, and email traces.
* Build an accurate event timeline by correlating PCAP data with VirusTotal’s submission and reputation history.
* Produce actionable threat intelligence while maintaining full operational safety inside an isolated VM.

---

## **Tools Used**
* VM: https://tryhackme.com/room/tsharkchallengesone
* **TShark** – command-line packet analysis, filtering (`-Y`), protocol hierarchy (`-z io,phs`), verbose inspection (`-V`), and artifact extraction.
* **VirusTotal** – domain/IP reputation check, submission timeline, and infrastructure mapping via the Relations tab.
* **CyberChef** – defanging URLs and IPs, decoding embedded payloads, and cleaning indicators for safe reporting.
* **Linux Terminal Utilities** – for redirection, pattern matching, and quick output parsing (`grep`, `nl`, `wc -l`).

---

# Investigation

# Task 1: Introduction

This room is about investigating traffic data as part of the SOC team using **TShark**.

- Start the VM with the green **Start Machine** button.
- The machine opens in split view, so no SSH/RDP needed.
- Important: **Exercise files are real**. Do **not** interact with them outside the VM, as they can pose security risks.

---

# Task 2: Case: Teamwork!

### Scenario

An alert was triggered:

> “The threat research team discovered a suspicious domain that could be a potential threat to the organisation.”
> 

We must investigate `teamwork.pcap` (located in `~/Desktop/exercise-files`) and create detection artefacts using **TShark** + **VirusTotal**.

---

## Q1. According to VirusTotal, what is the full URL of the malicious/suspicious domain address (defanged)?

**Step 1: Read the PCAP file**

I first looked at the raw capture with:

```bash
tshark -r teamwork.pcap --color
```

![image.png](image.png)

- Total packets: **793**
- While scrolling, I noticed interesting domains as part of a DNS queries
    
    ![image.png](image%201.png)
    

---

**Step 2: Check protocol hierarchy**

```bash
tshark -r teamwork.pcap -z io,phs -q
```

![image.png](image%202.png)

- Found **33 DNS frames**.
- DNS is always worth a deeper look.

---

**Step 3: Ran a display filter to filter on all DNS A queries:**

```bash
tshark -r teamwork.pcap -Y 'dns.qry.type == 1' --color | nl
```

![image.png](image%203.png)

- Output: **15 DNS A queries**.
- One stood out:
    
    ```
    www.paypal.com4uswebappsresetaccountrecovery.timeseaways.com
    ```
    
- Clearly malicious → looks like a **phishing domain**.

---

**Step 4: Defang the URL**

I used CyberChef → `Defang URL` recipe.

✅ **Answer:**

![image.png](image%204.png)

`www[.]paypal[.]com4uswebappsresetaccountrecovery[.]timeseaways[.]com`

---

## Q2. When was the URL of the malicious/suspicious domain first submitted to VirusTotal?

**Step 1:** Search the URL in VirusTotal.

Link: https://www.virustotal.com/gui/url/16db0aadc2423a67cd3a01af39655146b0f15d20dc2fd0e14b325026d8d1717e

**Step 2:** Go to **Details → History**.

![image.png](image%205.png)

- First submission date = **2017-04-17 22:52:53 UTC**

---

## Q3. Which known service was the domain trying to impersonate?

- From the URL itself:
    
    ```
    www.paypal.com4uswebappsresetaccountrecovery.timeseaways.com
    ```
    
- The first part = **PayPal** → clear impersonation.

---

## Q4. What is the IP address of the malicious domain? (defanged format)

**Step 1: Review DNS responses**

We already had this from DNS query filtering:

```bash
tshark -r teamwork.pcap -Y 'dns.qry.type == 1' --color | nl
```

Output:

![image.png](image%206.png)

Gonna focus on a specific packet, for example:

```
6 443 108.673854 75.75.75.75 → 192.168.1.100 DNS 136 Standard query response 0x60ea A www.paypal.com4uswebappsresetaccountrecovery.timeseaways.com A 184.154.127.226
```

The packet capture summary describes a DNS query and response:

- **Packet Number**: 443
- **Time**: 108.673854 seconds
- **Source**: 75.75.75.75 (DNS server)
- **Destination**: 192.168.1.100 (requesting machine)
- **Protocol**: DNS
- **Length**: 136 bytes
- **Info**: DNS query response for an A record
- **Query**: A record for `www.paypal.com4uswebappsresetaccountrecovery.timeseaways.com`
- **Response**: IP address 184.154.127.226 (the A record answer)

**Key Answer**

- The malicious domain resolved to: **184.154.127.226**

---

**Step 2: Cross-check with VirusTotal**

On the VT page of the query link, under **Relations**, the IP **184.154.127.226** also appeared.

![image.png](image%207.png)

De-fanged IP**:**`184[.]154[.]127[.]226`

---

## Q5. What is the email address that was used? (defanged format)

**Step 1: Search for HTTP requests with `.com`**

```bash
tshark -r teamwork.pcap -Y "http contains .com"
```

![image.png](image%208.png)

- Found suspicious traffic → `login.php`
- I will have to investigate this.
- We can look for the packet and show all data by using the following command with the use of the -V flag:

---

**Step 2: Inspect packet in detail**

```bash
tshark -r teamwork.pcap -Y "frame contains login.php" -V
```

![image.png](image%209.png)

- `-V` to show the packet data.

---

**Step 3: OR, to focus on Gmail traffic only** 

```bash
tshark -r teamwork.pcap -Y "http contains gmail.com" -V
```

![image.png](image%2010.png)

- Found the **stolen email** inside the packet data.
- It seems the person entered their initials on this false domain, and this way their credentials got snatched!

## **Findings**

* Detected malicious DNS queries attempting to impersonate **PayPal** via domain `www[.]paypal[.]com4uswebappsresetaccountrecovery[.]timeseaways[.]com`.
* Domain resolved to **184[.]154[.]127[.]226**, confirmed on VirusTotal as part of a long-running phishing campaign.
* VirusTotal’s history showed **first submission in 2017**, indicating recurring reuse of the infrastructure.
* HTTP inspection revealed **login form data** posting credentials to a fake PayPal page (`login.php`).
* Captured exfiltrated **Gmail address and password fields** in plaintext, confirming credential theft via phishing.
* Phishing kit leveraged DNS impersonation and HTTP POST exfiltration to mimic legitimate PayPal authentication flow.

---

## **Lessons Learned**

* TShark can fully replace Wireshark for phishing and credential theft analysis when used with smart filtering.
* **Protocol hierarchy (`-z io,phs`)** instantly guides where to start—DNS anomalies almost always tell the story.
* Inspecting with **-V** exposes stolen data directly in packet payloads without ever opening a GUI.
* Defanging IOCs before sharing ensures analyst safety and compliant threat reporting.
* VirusTotal’s **Relations and History tabs** transform a single indicator into full adversary context.
* Command-line packet analysis enables fast, repeatable, and automation-ready threat-hunting workflows.


# Socials

**Repository:** https://github.com/RahulCyberX/Network-Security-and-Traffic-Analysis

**Medium Article:** https://medium.com/@rahulcyberx/tshark-challenge-i-teamwork-tryhackme-walkthrough-2025-cc360bac6c65?source=your_stories_outbox---writer_outbox_published-----------------------------------------

**TryHackMe Profile:** https://tryhackme.com/p/0xRahuL

**Github Profile:** https://github.com/RahulCyberX
