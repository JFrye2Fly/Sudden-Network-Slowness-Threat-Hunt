# Sudden-Network-Slowness-Threat-Hunt

## Introduction

## Purview of the Threat Hunt <br>
### The server team has noticed a significant network performance degradation on some of their older devices attached to the network in the 10.0.0.0/16 network. After ruling out external DDoS attacks, the security team suspects something might be going on internally.

## Hypothesis <br>
All traffic originating from within the local network is by default allowed by all hosts. There is also unrestricted use of PowerShell and other applications in the environment. It’s possible someone is either downloading large files or doing some kind of port scanning against hosts in the local network.

<br><hr><br>
## Step 1 — Search different network requests from devices within the **10.0.0.x/16** subnet <br>

**The query below revealed that several devices from the 10.0.0.x/16 subnet were making Outbound requests to different IPs and different ports. A screenshot is below the query:**

<img width="1333" height="881" alt="Sudden Network Slowness #1" src="https://github.com/user-attachments/assets/983cbc0d-ff56-45ad-a77c-0b3d6ceebde2" />


<br><hr><br>
## Step 2 — Narrow down the search


<br>
<img width="1406" height="921" alt="Bruite Force attempts in last 7 days by Account Name and number of attempts" src="https://github.com/user-attachments/assets/e6898db8-cf4c-4ae0-8757-be28c37cc541" />
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

