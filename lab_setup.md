# ⚙️ Lab Setup Guide
**Project:** Splunk + Sysmon Reverse Shell Detection  
**Repository:** splunk-sysmon-reverse-shell-detection  

---

## 🏗️ 1. Lab Environment

### Virtual Machines
- **Windows 10 VM** (Victim)  
  - Sysmon installed  
  - Splunk Enterprise installed locally  
  - Defender disabled (for payload execution demo)  

- **Kali Linux VM** (Attacker)  
  - Tools: Metasploit Framework, msfvenom, Python web server  
  - Used to generate payload and launch reverse shell  

### Network
- VMware **Host-Only Network**  
- Ensures both VMs can communicate with each other but are isolated from the internet  

📸 *Insert screenshot of VMware network settings here*  

![VMware Network Setup](screenshots/vmware_network.png)

## 🖥️ 2. Windows 10 Configuration
### Step 1: Install Sysmon
1. Download Sysmon from [Sysinternals](https://chatgpt.com/g/g-p-68b957ff59d4819196105b82e2f4936f-mydfir-soc/c/68b95907-ca78-832d-bd74-96ccea5d3c8f#:~:text=Download%20Sysmon%20from-,Sysinternals,-Download%20Olaf%20Hartong%E2%80%99s)

2. Download Olaf Hartong’s Sysmon Modular Config
3. Extract Sysmon to C:\Sysmon
4. Install with config:
```ps
sysmon64.exe -i sysmonconfig.xml
```
