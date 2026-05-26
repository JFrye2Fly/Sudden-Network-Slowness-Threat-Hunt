# Sudden-Network-Slowness-Threat-Hunt

## Introduction

## Purview of the Threat Hunt <br>
### The server team has noticed a significant network performance degradation on some of their older devices attached to the network in the 10.0.0/16 network. After ruling out external DDoS attacks, the security team suspects something might be going on internally.

## Hypothesis <br>
All traffic originating from within the local network is by default allowed by all hosts. There is also unrestricted use of PowerShell and other applications in the environment. It’s possible someone is either downloading large files or doing some kind of port scanning against hosts in the local network.

<br><hr><br>
## Step 1 — Search different network requests from devices within the **10.0.0./16** subnet <br>

**The query below revealed that several devices from the 10.0.0.x/16 subnet were making Outbound requests to different IPs and different irregular ports. A screenshot is below the query:**

### **Query used:** <br>
***DeviceNetworkEvents 
| where LocalIP startswith "10.0.0"
| project Timestamp, DeviceName, LocalIP, RemoteIP, RemotePort, Protocol, InitiatingProcessFileName
| order by Timestamp desc***

<br>
<img width="1333" height="881" alt="Sudden Network Slowness #1" src="https://github.com/user-attachments/assets/983cbc0d-ff56-45ad-a77c-0b3d6ceebde2" />


<br><hr><br>
## Step 2 — Check which IPs had the most out outbound connections

**I decided to look at what 10.0.0 IPs had the most outbound connections and what I saw was astounding. Some devices on this network had over 2000 outbound connections. This definitely smells like a port scan or a compromised device reaching back out to a C2 server.**

### **Query used:** <br>
***DeviceNetworkEvents 
| where LocalIP startswith "10.0.0"
| summarize ConnectionsPerLocalIp=count() by DeviceName, LocalIP
| order by ConnectionsPerLocalIp desc***


<br>
<img width="1388" height="884" alt="Sudden Network Slowness #2" src="https://github.com/user-attachments/assets/19f10295-c454-4733-8155-d66ac59b670f" />
<br>

<br><hr><br>
## Step 3 — Look for suspicious Powershell Commands on "Jeffrey-test-v"

I decided to look into the DeviceProcessEvents table specifically for one of the apparently compromised VMs: "jeffrey-test-v" by using the query below: 

**| where DeviceName == "jeffreyf-test-v"
| where ProcessCommandLine has_any ("powershell.exe", "pwsh.exe", "curl", "Invoke-WebRequest")
| project Timestamp, ProcessCommandLine, AccountName
| order by Timestamp desc**

<br>

## By projecting the ProcessCommandLine and the AccountName I could see clearly that the account name "fryeguy" ran a portscan through using the command line to go through powershell to do the port scan... 

<br>
<img width="1377" height="893" alt="Sudden Network Slowness #5" src="https://github.com/user-attachments/assets/b70ebd5b-34cd-4d36-8bb4-c229668a7be8" />
<br>

<br><hr><br>
## Conclusion

In this Threat Hunt we tested our hypothesis was that Port Scanning or large file downloads were happening on several devices on the 10.0.0/16 network which was causing a lot of network slowness. Our hypothesis about Port Scanning was correct as we literally found a file calledd "portscan.ps1."

## Remediation steps:

- Isolate the affected device in Microsoft Defender for Endpoint to stop further scanning or lateral movement.
- Investigate the initiating process/user account (powershell.exe, nmap.exe, cmd.exe, etc.) and determine whether credentials were compromised.
- Hunt for follow-on activity such as SMB/RDP access attempts, remote execution, scheduled tasks, or malware downloads.
- Block or restrict the device’s internal network access using firewall rules, segmentation, or NAC controls.
- Remediate persistence/malware, rotate compromised credentials, and harden the environment (limit PowerShell, enforce least privilege, tighten internal firewall rules).
