# 🛡️ Endpoint Detection Lab with Splunk & Sysmon

## 📖 Overview
This project demonstrates detecting malicious endpoint activity with **Sysmon** and **Splunk** in a VMware lab.  
A **reverse shell attack** was simulated from Kali Linux against a Windows 10 VM. Sysmon telemetry was ingested into Splunk and analyzed to trace the attack.

---

## 🎯 Objectives
- Configure **Sysmon** on Windows 10 for endpoint telemetry
- Ingest logs into **Splunk Enterprise**
- Simulate a **reverse shell attack** from Kali Linux with Metasploit
- Detect suspicious network connections and child processes in Splunk
- Investigate the attack timeline using Sysmon + Splunk correlation

---

## 🏗️ Lab Architecture

![Lab Setup](screenshots/Screenshot_2025-09-10_053151.png)

---

## ⚙️ Setup & Configuration

### Windows 10 VM
- Installed **Sysmon** with modular configuration
- Installed **Splunk Enterprise**
- Configured `inputs.conf` to send Sysmon logs to `index=endpoint`
- Restarted **Splunkd service**

### Splunk
- Created a new index: endpoint
- Installed Splunk Add-on for Sysmon
- Verified Sysmon logs ingestion

---

## 🚨 Attack Simulation (Red Team)
1. **Recon**: Scanned victim with Nmap from Kali
2. **Payload**: Generated reverse TCP payload (Resume.pdf.exe) with Metasploit
3. **Delivery**: Hosted payload on Kali with Python HTTP server (python3 -m http.server 9999)
4. **Execution**: Downloaded + executed payload on Windows 10
5. **Exploitation**: Reverse shell established back to Kali (Meterpreter session)
6. **Post-Exploitation**: Enumerated users, groups, and network info

![msf6 multi handler](screenshots/1_home-lab.png)

![msf6 multi handler](screenshots/2-home_lab.png)

---

## 🔍 Detection in Splunk (Blue Team)
![splunk index=endpoint](screenshots/2025-09-11-050056.png)

### 1. Broad Search - Reviewing Network Connections
Started with a broad search for all Sysmon EventCode 3 (Network Connections):
```spl
index=endpoint EventCode=3
```
![splunk Event Code 3](screenshots/2025-09-11-050526.png)

This will return all outbound connections from the Windows 10 VM.

---

![splunk Event Code 3 Results](screenshots/2025-09-11-050745.png)

From this search, an outbound connection was discovered to a suspicious port: TCP 4444.

---

### 2. Suspicious Network Connection (Discovery)
Refined the search to identify traffic to the attacker’s IP and port:

```spl
index=endpoint EventCode=3 dest_ip=192.168.117.130 dest_port=4444 
```

![splunk Dest Port and Source IP](screenshots/2025-09-11-053336.png)

After we spot the suspicious port we find the ip address where connection is coming from with `dest_ip`

---

Once can pin point the odd traffic we then can refine our search using `EventCode` this time using EventCode 1.

![splunk Dest Port and Source IP](screenshots/2025-09-11-053730.png)

---

### 3. Malicious Binary Execution (Root Cause Analysis)

Pivoted to Event Code 1 (Process Creation) we spot a suspicious process `Resume.pdf.exe` 

![splunk process exec Resume.pdf.exe](screenshots/2025-09-11-051136.png)

---

### 4. Suspicious Child Processes (Process Tree Investigation)
Investigated the process tree to confirm parent/child relationships:
```spl
index=endpoint Resume.pdf.exe EventCode=1
```
![Suspicious Process Tree1](screenshots/2025-09-11-054719.png)

Expand the data to gain more information

![Suspicious Process Tree2](screenshots/2025-09-11-055024.png)

Confirmed Resume.pdf.exe spawned cmd.exe, which later invoked PowerShell for payload execution.

---

### 5. Timeline of Attack (Correlating Activity by GUID)
Reconstructed the full attack chain using process GUID:
```spl
index=endpoint {8519ae3f-07b6-68c0-ea0a-000000001500}
| table _time,ParentImage,Image,CommandLine
```
![Attack Timeline](screenshots/2025-09-11-055451.png)

---
 
## 📑 Findings
- Reverse shell established from victim → attacker on TCP/4444
- Malicious binary `Resume.pdf.exe` was executed from the Downloads folder
- Sysmon Event ID 1 (Process Creation) confirmed it spawned `cmd.exe` and `powershell.exe`
- Sysmon Event ID 3 (Network Connection) confirmed outbound traffic to attacker IP
- Attack chain: `Resume.pdf.exe → cmd.exe → powershell.exe → reverse shell`

## ✅ Conclusion
This lab demonstrates a full SOC workflow:
1️⃣ Detecting anomalous network activity (reverse shell on TCP 4444)
2️⃣ Pivoting into endpoint process telemetry to identify the root cause
3️⃣ Mapping the attack chain through parent/child process correlation
4️⃣ Reconstructing the timeline of adversary behavior

📈 Skills Demonstrated:

- Endpoint monitoring with Sysmon
- SIEM analysis with Splunk SPL queries
- Threat emulation with Metasploit
- Incident investigation & reporting

## 📂 Repository Structure
```perl
splunk-sysmon-reverse-shell-detection/
│── README.md             # Project landing page
│── lab_setup.md          # Setup instructions
│── attack_simulation.md  # Adversary steps
│── detection_queries.md  # Splunk SPL queries
│── screenshots/          # Evidence
│── report.pdf            # Professional write-up
```
## 🔗 References
- [Sysmon (Sysinternals)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Splunk Enterprise](https://www.splunk.com/en_us/download/splunk-enterprise.html)
- [Metasploit Framework](https://www.metasploit.com/)
- [Olaf Hartong Sysmon Modular Config](https://github.com/olafhartong/sysmon-modular)
