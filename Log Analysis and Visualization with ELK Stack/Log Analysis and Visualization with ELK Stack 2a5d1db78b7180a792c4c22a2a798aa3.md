# Log Analysis and Visualization with ELK Stack

## **Objectives**

* Investigate January 2022 VPN connection logs using Kibana’s Discover, Visualize, and Dashboard modules inside Elastic Stack.
* Query and filter logs with **KQL** to detect post-termination access by ex-employee **Johny Brown**.
* Analyze failed logins, top source IPs, and anomalous geolocations through dynamic time-series filtering.
* Build and organize visualizations (tables, pie charts, bar graphs) into a SOC-ready dashboard.
* Derive actionable insights and confirm post-employment access attempts in a safe, browser-based lab.

---

## **Tools Used**
- VM: https://tryhackme.com/room/investigatingwithelk101
* **Kibana** (Discover, Visualize, Dashboard — filtering, field toggling, time brushing, object saving)
* **KQL (Kibana Query Language)** (field queries, wildcards, AND/OR/NOT logic, timestamp filters)
* **Elasticsearch** (data storage and indexed search)
* **Logstash + Beats** (data ingestion and normalization pipeline)
* **vpn_connections index** (real January 2022 VPN logs from CyberT)

---

# Task 1: Introduction

In this task, I learned how to use the **Kibana interface** for searching, filtering, creating visualizations, and building dashboards while investigating VPN logs.

---

### **Learning Objectives**

- Perform searches and apply filters in Kibana.
- Save searches for future use.
- Create visualizations to understand log data better.
- Investigate VPN logs to identify anomalies.
- Build dashboards using saved searches and visualizations.

---

# Task 2: Incident Handling Scenario

### **Goal**

Understand the investigation scenario before analyzing logs.

![93bf216574fb435bef51b890a741e4cb.png](93bf216574fb435bef51b890a741e4cb.png)

---

### **Scenario Summary**

- Company: **CyberT (US-based)**
- Dataset: **VPN logs (January 2022)** stored in the **index vpn_connections**
- User “**Johny Brown**” was **terminated on 1st January 2022**
- Multiple **failed connection attempts** were observed and needed investigation

---

# Task 3: ElasticStack Overview

### **Goal**

Understand the **Elastic Stack (ELK Stack)** components and how they interact to collect, store, process, and visualize data.

![f858c0d22d015b663438dae207981532.png](f858c0d22d015b663438dae207981532.png)

---

### **Step 1: Learn Each Component**

| Component | Function |
| --- | --- |
| **Elasticsearch** | Core search and analytics engine; stores and queries data in JSON format via RESTful API. |
| **Logstash** | Processes and normalizes incoming data using **Input**, **Filter**, and **Output** pipelines. |
| **Beats** | Lightweight agents that ship data (e.g., **Winlogbeat** for Windows logs, **Packetbeat** for network traffic). |
| **Kibana** | Visualization and dashboard tool used for searching and analyzing data stored in Elasticsearch. |

---

### **Step 2: Understand Workflow**

![ec4f681a412aa825b284523dcd5b8650.png](ec4f681a412aa825b284523dcd5b8650.png)

1. **Beats** collect raw data from endpoints.
2. **Logstash** filters and processes it.
3. **Elasticsearch** indexes and stores the structured data.
4. **Kibana** visualizes and allows interaction through dashboards and queries.

---

# Task 4: Kibana Overview

![79666633db3996dd33925223bae09e46.png](79666633db3996dd33925223bae09e46.png)

### **Goal**

Familiarize myself with Kibana’s interface and its primary tabs used for log analysis.

---

### **Main Features Covered**

- **Discover Tab:** Search and filter logs.
- **Visualization Tab:** Create visual reports and charts.
- **Dashboard Tab:** Combine multiple visualizations and searches into one view.

---

### **Lab Connection Info**

- Connect via VPN or AttackBox.
- Use credentials:
    
    ```
    Username: Analyst
    Password: analyst123
    ```
    
- Waited 3–5 minutes for the machine to start and access via `MACHINE_IP` .

---

# Task 5: Discover Tab

### **Goal**

Use the **Discover tab** to filter, explore, and investigate VPN logs.

![9635453d465f7625f5dfda21966aa6a6.png](9635453d465f7625f5dfda21966aa6a6.png)

---

Some key information available in a dashboard interface are

1. **Logs (document):** Each log here is also known as a single
document containing information about the event. It shows the fields and values found in that document.
2. **Fields pane**: Left panel
of the interface shows the list of the fields parsed from the logs. We
can click on any field to add the field to the filter or remove it from
the search.
3. **Index Pattern:** Let the user select the index pattern from the available list.
4. **Search bar:** A place where the user adds search queries / applies filters to narrow down the results.
5. **Time Filter:** We can narrow down results based on the time duration. This tab has many options to select from to filter/limit the logs.
6. **Time Interval:** This chart shows the event counts over time.
7. **TOP Bar:** This bar contains various options to save the search, open the saved searches, share or save the search, etc.

### **Step 1: Understanding Key Features**

- **Logs/Documents:** Each event = one document.
- **Search Bar:** Enter queries or filters.
- **Time Filter:** Adjust time range to narrow results.
    
    ![3691fb78e08f98b9b825fa6eaeefcf91.png](3691fb78e08f98b9b825fa6eaeefcf91.png)
    
- **Timeline Chart:** Shows event spikes over time.
    
    ![5a2096f7dac927eaeb020c2c81e15565.png](5a2096f7dac927eaeb020c2c81e15565.png)
    
- **Fields Pane:** Filter or visualize based on fields like `Source_IP`, `UserName`, etc.
    
    ![aa7c29f3d971ce34a6f69c0dd9b1be86.png](aa7c29f3d971ce34a6f69c0dd9b1be86.png)
    
- **Create Table:** Customize and save selected columns for analysis.
    
    ![ed538dabafffd64020b51f88fabce8f9.gif](ed538dabafffd64020b51f88fabce8f9.gif)
    

---

### **Step 2: Tasks and Steps**

### 🔹 Filter Logs by Date

- Used the **Time Filter** (top-right) to select `31 Dec 2021 → 2 Feb 2022`.
- Pressed **Refresh** to apply the range.
    
    ![Screenshot-2025-04-22-at-21.30.55-2048x660.png.webp](Screenshot-2025-04-22-at-21.30.55-2048x660.png.webp)
    

---

### 🔹 Find IP with Max Connections

- In **Fields Pane**, selected `Source_IP`.
    
    ![Screenshot-2025-04-22-at-21.34.59.png.webp](Screenshot-2025-04-22-at-21.34.59.png.webp)
    
- Checked the **Top Values** list.

---

### 🔹 Find User with Max Traffic

- Selected `UserName` field.
- Viewed top listed usernames.
    
    ![Screenshot-2025-04-24-at-20.00.24-1120x867.png.webp](Screenshot-2025-04-24-at-20.00.24-1120x867.png.webp)
    

---

### 🔹 Create Custom Table

- Added fields: `IP`, `UserName`, `Source_Country`.
- Used **“Toggle column in table”** to include them.
    
    ![Screenshot-2025-04-24-at-20.05.31-2048x966.png.webp](Screenshot-2025-04-24-at-20.05.31-2048x966.png.webp)
    

---

### 🔹 Filter by User “Emanda”

- In **UserName** field → clicked **+** beside *Emanda* to filter only her logs.
    
    ![Screenshot-2025-04-24-at-20.06.23-1142x867.png](Screenshot-2025-04-24-at-20.06.23-1142x867.png)
    
- Selected `Source_IP` → checked top value.
    
    ![Screenshot-2025-04-24-at-20.08.16-1146x867.png.webp](Screenshot-2025-04-24-at-20.08.16-1146x867.png.webp)
    

---

### 🔹 Find IP Causing Spike (11 Jan)

- Removed “Emanda” filter.
- On **Timeline Chart**, selected the bar for **11 Jan**.
    
    ![Screenshot-2025-04-24-at-20.11.29-1300x388.png.webp](Screenshot-2025-04-24-at-20.11.29-1300x388.png.webp)
    
- Checked top Source IP values.
    
    ![Screenshot-2025-04-24-at-20.10.27-1300x867.png.webp](Screenshot-2025-04-24-at-20.10.27-1300x867.png.webp)
    

---

### 🔹 Exclude New York State

- Filtered by **Source_IP = 238.163.231.224**.
    
    ![Skaermbillede-2025-06-03-133724.png.webp](Skaermbillede-2025-06-03-133724.png.webp)
    
- Added a **negative filter (–)** on **Source_State = New York**.
- Checked total remaining documents.

---

# Task 6: KQL Overview

### **Goal**

In this task, I learned to use **Kibana Query Language (KQL)** to search and filter logs in Elasticsearch using both **free text** and **field-based** searches.

![3327ee49838ed3b50aa9ffca5295b271.png](3327ee49838ed3b50aa9ffca5295b271.png)

---

### **Step 1: Understanding KQL Basics**

### **Free Text Search**

- Typing any word (e.g., `security`) returns all logs containing that term.
- Searches match **whole words only** (e.g., `United` ≠ `United States`).
- Use **wildcards** like `United*` to include partial matches.
    
    ![e4ce12cedbed2b6c7d5519d49a000881.png](e4ce12cedbed2b6c7d5519d49a000881.png)
    

### **Logical Operators**

KQL supports:

- `OR` — combines multiple conditions
    
    → Example: `"United States" OR "England"`
    
- `AND` — matches logs containing both conditions
    
    → Example: `"United States" AND "Virginia"`
    
- `NOT` — excludes specified results
    
    → Example: `"United States" AND NOT ("Florida")`
    

### **Field-Based Search**

- Format: `FIELD : VALUE`
    
    → Example: `Source_ip : 238.163.231.224 AND UserName : Suleman`
    
- Kibana auto-suggests available fields while typing.

---

### **Step 2: Using KQL to Filter Data**

### **Filter logs from Source_Country = United States and show logs for User James or Albert**

- Query used:
    
    ```
    Source_Country : "United States" and (UserName : "James" or UserName : "Albert")
    ```
    

**Answer:** 161 records

---

### **Find VPN connections after termination of user “Johny Brown” (1 Jan 2022)**

- Query used:
    
    ```
    UserName: "Johny Brown" and @timestamp > "2022-01-01T00:00:00.000Z"
    ```
    

**Answer:** 1 record

---

# Task 7: Creating Visualizations

### **Goal**

Learn how to convert log data into clear visual insights using the **Visualization tab** in Kibana.

---

### **Step 1: Creating Visualizations**

- From **Discover tab**, select any field → click **“Visualize”**.
- Choose chart type (e.g., table, pie chart, bar chart).

Example:

- To visualize top 5 source countries:
    - Use **Source_Country** field.
    - Choose a **Pie Chart** to display country-wise log distribution.

---

### **Step 2: Correlation Views**

![e5f27f38815a495499935f5a373728a6.png](e5f27f38815a495499935f5a373728a6.png)

- Drag multiple fields (e.g., `Source_Country` vs `Source_IP`) into the center panel to compare relationships between them.

---

### **Step 3: Saving and Sharing**

![432f67edc84fff2cb9e6fc7bb6243b1b.png](432f67edc84fff2cb9e6fc7bb6243b1b.png)

1. Click **Save** (top-right).
2. Add a descriptive **title** and **description**.
3. Choose to add to an existing or new **dashboard**.
4. Click **Save and add to library**.

---

### **Step 4: Analyzing Data**

### **User with most failed login attempts**

- Visualized `UserName` vs `action` in a table view.
    
    ![Skaermbillede-2025-06-03-135233.png.webp](Skaermbillede-2025-06-03-135233.png.webp)
    
- Sorted results on `failed` actions.
    
    ![Skaermbillede-2025-06-03-140353.png.webp](Skaermbillede-2025-06-03-140353.png.webp)
    

---

### **Total wrong VPN connection attempts in January**

- Added `action` on the x-axis, grouped by `@timestamp`, and used `count()` on y-axis.
    
    ![Skaermbillede-2025-06-03-141350.png.webp](Skaermbillede-2025-06-03-141350.png.webp)
    
- Identified total failed attempts in January.
    
    **Answer:** 274
    

---

# Task 8: Creating Dashboards

### **Goal**

Combine all saved visualizations into a single interactive **Kibana dashboard**.

---

### **Steps to Create a Dashboard**

1. Open the **Dashboard tab**.
2. Click **“Create dashboard”**.
    
    ![2b8beb35c48052335e21479f096e2cf2.png](2b8beb35c48052335e21479f096e2cf2.png)
    
3. Use **“Add from Library”** to import saved visualizations.
4. Arrange and resize as desired for clarity.
5. Click **Save** to finalize layout and preserve structure.

---

## **Findings**

* Post-termination user **Johny Brown** logged one VPN connection attempt **after January 1, 2022**.
* Major failed login spike detected on **11 January 2022**, linked to **Source IP 238.163.231.224 (New York)**.
* Excluding **Source_State = New York** revealed multiple additional failed logins from other regions.
* User **Emanda** generated consistent high-volume connections, dominating top user activity metrics.
* Total **failed VPN connection attempts: 274** during January 2022.
* Custom SOC dashboard consolidated user logins, source countries, and failed attempt trends for quick monitoring.

---

## **Lessons Learned**

* Always set **Time Filter** and index before starting any search — it defines your investigation scope.
* **Fields pane Top Values** instantly highlights dominant IPs and usernames without manual KQL.
* **KQL queries** combine clarity and power — one line isolates post-termination activity precisely.
* **Timeline brushing** exposes event spikes like brute-force waves within seconds.
* **Negative filters** efficiently remove geographic noise and reveal real anomalies.
* Elastic Stack’s browser-only workflow enables complete SOC investigations safely and efficiently.


# Socials

**Repository:** https://github.com/RahulCyberX/Security-Information-Event-Management

**Medium Article:** https://medium.com/@rahulcyberx/investigating-with-elk-101-complete-tryhackme-walkthrough-250cce44a0ef?source=your_stories_outbox---writer_outbox_published-----------------------------------------

**TryHackMe Profile:** https://tryhackme.com/p/0xRahuL

**Github Profile:** https://github.com/RahulCyberX
