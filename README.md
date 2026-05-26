# Sudden-Network-Slowness-Threat-Hunt

## Introduction

## Purview of the Threat Hunt <br>
### The server team has noticed a significant network performance degradation on some of their older devices attached to the network in the 10.0.0.0/16 network. After ruling out external DDoS attacks, the security team suspects something might be going on internally.

## Hypothesis <br>
All traffic originating from within the local network is by default allowed by all hosts. There is also unrestricted use of PowerShell and other applications in the environment. It’s possible someone is either downloading large files or doing some kind of port scanning against hosts in the local network.

<br><hr><br>
## Step 1 — Search different network requests from devices within the **10.0.0.x/16** subnet <br>

**The query below revealed that several devices from the 10.0.0.x/16 subnet were making Outbound requests to different IPs and different irregular ports. A screenshot is below the query:**

**Query used:** <br>
***DeviceNetworkEvents 
| where LocalIP startswith "10.0.0"
| project Timestamp, DeviceName, LocalIP, RemoteIP, RemotePort, Protocol, InitiatingProcessFileName
| order by Timestamp desc***

<br>
<img width="1333" height="881" alt="Sudden Network Slowness #1" src="https://github.com/user-attachments/assets/983cbc0d-ff56-45ad-a77c-0b3d6ceebde2" />


<br><hr><br>
## Step 2 — Check which IPs had the most out outbound connections

**I decided to look at what 10.0.0 IPs had the most outbound connections and what I saw was astounding. Some devices on this network had over 2000 outbound connections. This definitely smells like a port scan or a compromised device reaching back out to a C2 server.**

**Query used:** <br>
***DeviceNetworkEvents 
| where LocalIP startswith "10.0.0"
| summarize ConnectionsPerLocalIp=count() by DeviceName, LocalIP
| order by ConnectionsPerLocalIp desc***


<br>
<img width="1388" height="884" alt="Sudden Network Slowness #2" src="https://github.com/user-attachments/assets/19f10295-c454-4733-8155-d66ac59b670f" />
<br>

<br><hr><br>
## Step 3 — Check for any successful logon attempts after failed logon attempts

***Query used:*** <br>



<br>
<img width="1201" height="880" alt="No successful logon to the Windows VM after Brute Force attempt" src="https://github.com/user-attachments/assets/bd1b76cc-7213-4391-b9de-a3c01ba3b743" />
<br>

<br><hr><br>
## Conclusion

In this Threat Hunt we tested our hypothesis that during the time this VM was exposed to the internet someone might have gained access through Brute Force Logins. Luckily no one gained access to the VM and we created a detection rule to alert us in the future. Super strong passwords that are not used on other accounts such be required to combat against Brute Force logons. 

