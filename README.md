# 🛡️ Endpoint Detection Lab with Splunk & Sysmon

## 📖 Overview
This project demonstrates detecting malicious endpoint activity with **Sysmon** and **Splunk** in a VMware lab.  
A reverse shell attack was simulated from Kali Linux against a Windows 10 VM. Sysmon telemetry was ingested into Splunk and analyzed to trace the attack.

---

## 🎯 Objectives
- Configure **Sysmon** on Windows 10 for endpoint telemetry
- Ingest logs into **Splunk Enterprise**
- Simulate a **reverse shell attack** from Kali Linux with Metasploit
- Detect suspicious network connections and child processes in Splunk
- Investigate the attack timeline using Sysmon + Splunk correlation

---

## 🏗️ Lab Architecture

![Lab Setup](screenshots/vmware_lab.png)

 Sysmon + Splunk Enterprise
## ⚙️ Setup & Configuration
- Windows 10 VM → Installed Sysmon + Splunk Enterprise
- Configured `inputs.conf` to send Sysmon logs to `index=endpoint`
- Kali Linux VM → Recon, payload generation, reverse shell
- Verified ingestion of Sysmon events in Splunk

## 🚨 Attack Simulation
- Generated malicious payload (`Resume.pdf.exe`) using Metasploit
- Hosted payload on Kali via Python HTTP server
- Executed payload on Windows 10 VM → reverse shell established
- Post-exploitation: enumerated users, groups, and network details
- 📸 (Insert screenshot here)

## 🔍 Detection in Splunk

### Query 1: Malicious Binary Execution
```spl
index=endpoint Resume.pdf.exe


---

### 8. **Findings & Results**
Show what you uncovered.  
```markdown
## 📑 Findings
- Reverse shell established from victim → attacker on TCP/4444
- `Resume.pdf.exe` spawned `cmd.exe` (suspicious child process)
- Correlated Sysmon Event IDs 1 (process creation) + 3 (network connection)
- Attack chain mapped: Resume.pdf.exe → cmd.exe → powershell.exe → reverse shell

## ✅ Conclusion
This lab demonstrates how endpoint telemetry and SIEM analysis can be used to detect and investigate adversary activity.  
It highlights essential SOC analyst skills:
- Endpoint monitoring (Sysmon)  
- Log analysis & correlation (Splunk)  
- Threat emulation (Metasploit)  
- Incident investigation workflows  

## 📂 Repository Structure
splunk-sysmon-reverse-shell-detection/
│── README.md             # Project landing page
│── lab_setup.md          # Setup instructions
│── attack_simulation.md  # Adversary steps
│── detection_queries.md  # Splunk SPL queries
│── screenshots/          # Evidence
│── report.pdf            # Professional write-up

## 🔗 References
- [Sysmon (Sysinternals)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Splunk Enterprise](https://www.splunk.com/en_us/download/splunk-enterprise.html)
- [Metasploit Framework](https://www.metasploit.com/)
- [Olaf Hartong Sysmon Modular Config](https://github.com/olafhartong/sysmon-modular)
