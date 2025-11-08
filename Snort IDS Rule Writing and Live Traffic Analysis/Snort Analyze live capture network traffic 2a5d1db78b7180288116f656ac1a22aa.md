# Snort: Analyze live capture network traffic

I just cleared Snort Challenge - The Basics and it was the perfect hands-on follow-up to the intro room. Everything runs safely inside an isolated virtual machine with pre-loaded pcaps and empty rule files, so no real network gets touched. The goal is straightforward: level up from just running Snort to actually writing your own detection rules for common protocols and tricky scenarios. I spent the whole time crafting alerts for HTTP and FTP traffic, spotting payload sizes, hunting torrent files with content matching, fixing broken rules that wouldn't fire, and even pulling out details from EternalBlue exploits. By the end I could turn vague ideas like "find big packets" into working signatures that lit up exactly the right alerts. Felt great to see my custom rules catch stuff in real pcaps without any hand-holding.

Virtual Machine Provided in: https://tryhackme.com/room/snortchallenges2

## Tools Used

Snort, vim (editing rules), Base64Decode 

# Investigation

This project is all about practicing Snort by writing custom IDS rules and analyzing `.pcap` traffic captures. 

## Writing IDS Rules (HTTP)

I open the folder which has a captured traffic, and then i make a rules file called local.rules which i can use as config when reading the example traffic capture. 

I open the local.rules file using `nano local.rules` and write this code so that I can detect all TCP packets from or to port 80:

![image.png](image.png)

But we can do this in a single line so let’s do this instead:

![image.png](image%201.png)

After that I run this command to run snort for analyzing this captured traffic packet and use my filter

![image.png](image%202.png)

- `c local.rules` → use my rules file
- `A full` → print full alert output
- `l .` → log to current directory
- `r mx-3.pcap` → read packets from the capture file

Once the analysis is done I can clearly see the number of packets it detected:

![image.png](image%203.png)

So, the total number of detected packet is = 60. 

To analyze a specific packet X, where X = 63 (for example), we need to filter the traffic of packet 63 only in our log that we got after analyszing this traffic packet.

![image.png](image%204.png)

![image.png](image%205.png)

After the analysis we can easily see these details as well:

![image.png](image%206.png)

- Source address: `145.254.160.237`, source port `3371`
- Destination address: `216.239.59.99`, source port `80`
- TTL of packet 63: `128`
- SEQ number: `0x36C21E28`
- ACK number: `0x2E6B5384`

## Writing IDS Rules (FTP)

For this i am gonna analyze a different traffic packet and detect “all TCP port 21” traffic. 

![image.png](image%207.png)

And now I am gonna run snort for analyze this pcap.

![image.png](image%208.png)

![image.png](image%209.png)

Let’s read it’s log file to find out the FTP service name, by using the `strings` command, which can be combined with `grep` too. 

![image.png](image%2010.png)

Service name = Microsoft FTP Service.

Now i am gonna do some interesting detentions using the status codes. 

### Rule to detect Failed FTP logins:

First i am gonna remove previous logs using `sudo rm -f snort.log.*` and then use the nano text editor to add the following rule:

![image.png](image%2011.png)

![image.png](image%2012.png)

Failed Login attempts = **41**

### Rule to detect Successful FTP logins:

![image.png](image%2013.png)

![image.png](image%2014.png)

Successful Logins = 1

### Rule to detect FTP login attempts with Valid username but no/bad password:

```jsx
alert tcp any 21 -> any any (msg:"FTP login no pass";content:"331";sid:1000007;rev:1;)
```

### Rule to detect FTP login attempts with “Administrator” username but no/bad password:

```jsx
alert tcp any 21 -> any any (msg:"FTP admin no pass";content:"331";content:"Administrator";sid:1000008;rev:1;)
```

Status code: 

- `530` (Not logged in)
- `230` ****(User logged in, proceed)
- `331`  (Username okay, need password)

## Writing IDS Rules (PNG/GIF)

Here I detect image files using **magic numbers** (file signatures).

PNG files start with hex: `89 50 4E 47 0D 0A 1A 0A`

GIF magic hex: 

- `47 49 46 38 39 61` (`GIF89a`) or
- `47 49 46 38 37 61` (`GIF87a`).

![image.png](d1ae99f3-2b11-438b-9665-557ffe1b6271.png)

Then run:

```jsx
sudo snort -r ftp-png-gif.pcap -c local.rules -l .
```

![image.png](image%2015.png)

There is one PNG file, lets find our the software name embedded in it:

```jsx
sudo strings snort.log.1757949848 | less
```

![image.png](image%2016.png)

Now I am gonna write rule to detect the GIF file in the given pcap and identify the image format it’s embedded in by investigating the logs. 

GIF magic hex: `47 49 46 38 39 61` (`GIF89a`) or `47 49 46 38 37 61` (`GIF87a`). 

It’s possible to just match prefix `|47 49 46 38|` to match either, then during investigation I can confirm the format easily. 

![image.png](image%2017.png)

Let’s run snort:

```jsx
 sudo snort -r ftp-png-gif.pcap -c local.rules -l . 
```

![image.png](image%2018.png)

As I can see, there’s 4 instances of a GIF image. To find their format I am gonna investigate the log file and use a `grep` command as well to search for the keyword “GIF” to see 

![image.png](image%2019.png)

This confirms the format of GIF are: **GIF89a.**

## Writing IDS Rules (Torrent Metafile)

I can write a simple run to detect any torrent meta file by adding `.torrent` in the content section of the tcp alert rule. 

1. **Rule**:
    
    ```
    alert tcp any any <> any any (msg:".torrent file detected"; content:"torrent"; sid:1000000000009; rev:1;)
    ```
    
2. Run:

```jsx
sudo snort -r torrent.pcap -c local.rules -l .
sudo strings snort.log.<timestamp> | less
```

In the log file, we can easily find more info regarding the torrent, such as **torrent app name, MIME type, and hostname.**

## Miscellaneous Rules

[Source](https://www.jalblas.com/blog/thm-snort-challenge-the-basics-walkthrough/#task-7-using-external-rules-ms-17-010) for the screenshots below, as I forgot to take my own screenshots when I was doing it. 

1. A new rule to detect payloads containing the "\IPC$" keyword:

```jsx
alert tcp any any <> any any (msg:"Keyword found"; content:"\\IPC$"; sid:1000000000010; rev:1;)
```

(special char `\` must be escaped or hex)

OR

```jsx
alert tcp any any -> any any (msg: "Exploit Detected!"; content: "IPC$"; sid:1000001; rev: 1;)
```

1. To see how many rules were triggered:

Just below the alarm info I can see that there’s an another section called *Limits*. Under this section there are the number of events. This is equal to the number of triggered rules.

![image.png](image%2020.png)

By scrolling further below I can find the info on the filtered events, such as **sids**

![image.png](image%2021.png)

1. New rule to detect packet payloads between A and B bytes, for example between **770 and 855** bytes:

There are even examples, so the rule value would be dsize:770<>855;.

All together this will look like:

```jsx
alert tcp any any -> any any (msg:"Size between 770 and 855 bytes detected"; dsize:770<>855; sid:1000001; rev:1;)
```

1. A way to find name of the used encoding algorithm:

`snort -r snort.log.<timestamp> -dev`

![image.png](image%2022.png)

1. A way to find the encoded command:

The base64 encoded command is found right after Base64/, still in the same packet:

![image.png](image%2023.png)

To decode this encoded message, for conveince I just copied the string and pasted it in [https://www.base64decode.org/](https://www.base64decode.org/), the output:

![image.png](image%2024.png)

## Lessons Learned

- Rule structure looks intimidating at first but it's just action-protocol-source-destination plus options like msg, sid, and content.
- Always test on the exact pcap provided—small changes in direction (<> vs ->) can half your alert count.
- Bidirectional rules with <> save time when you want both inbound and outbound without duplicates.
- Content matching is insanely powerful for strings like ".torrent" or hex signatures in hidden files.
- Payload size checks with dsize:770<>855 catch weird packets no port filter would.
- Fixing syntax errors in someone else's rule teaches way more than writing perfect ones from scratch.
- External community rules for big CVEs like MS17-010 drop straight in and just work.
- Reading alert logs with -A full gives you full packet details when console mode isn't enough.
- All this in a safe VM means I can experiment wildly and break things until the alerts finally match.

## Socials

**Repository:** https://github.com/RahulCyberX/Network-Security-and-Traffic-Analysis

**Medium Article:** https://medium.com/@rahulcyberx/snort-challenge-the-basics-tryhackme-writeup-2025-64200ec0120e?source=your_stories_outbox---writer_outbox_published-----------------------------------------

**TryHackMe Profile:** https://tryhackme.com/p/0xRahuL

**Github Profile:** https://github.com/RahulCyberX