# Snort-IDS-and-Honeypot-Integration
This project aims to enhance network security by deploying and integrating a Pentbox honeypot with a Snort Intrusion Detection System (IDS). This combination will provide a proactive defense mechanism by attracting and analyzing attackers while keeping critical systems protected.

# Installation
1. Virtual Machiine = [Link](https://www.virtualbox.org/wiki/Downloads)

2. Kali Linux for Attack = [Link](https://www.kali.org/get-kali/#kali-installer-images)

3. Ubuntu OS System for IDS with Snort and Pentbox Honeypot = [Link](https://ubuntu.com/download/desktop)

4. Two Routers for Internet Connection and create a Network Infrastruction

# Implementation
1. INSTALL URUNTU (LINUX OS) SYSTEM
   
•	Install Ubuntu on a dedicated machine or virtual machine. This will be used for Snort.
•	A lightweight Linux distribution like Debian is recommended for the honeypot (Pentbox).

3. INSTALL SORT TOOL
   
• Install Snort on the Ubuntu system. This typically involves downloading the Snort package, configuring dependencies, and compiling/installing.
  
5. IP GATHERING
   
•	Gather IP addresses:
o	Identify the IP address of the Ubuntu system where Snort is installed.
o	Determine the IP address that the Pentbox honeypot will use. This IP should be on an isolated network segment.
•	(This step might be better named "Network Configuration")

6. UNZIPPING PENTBOX PACKAGES

•	Unzip the Pentbox package on the Debian system.


7. INSTALLATION PENTBOX HONEYPOT

•	Install Pentbox on the Debian system. This likely involves extracting the Pentbox files and potentially running an installation script.
 
8. CHECKING 0 HOST UP IN ATTACKING MACHINE

•	This step is unclear and requires more context. It seems to refer to a check from the attacker's perspective, verifying that the honeypot appears to be a live host.
•	Clarification is needed on what "0 host up" specifically means.

 
9. SETTING UP  PENTBOX HONEYPOT

•	Configure Pentbox to simulate the desired services (e.g., SSH, Telnet). This involves editing Pentbox configuration files.


10. ACTVATE HONEYPOT ON ANYPOT

•	This step is unclear. It likely refers to starting the Pentbox honeypot service.
•	Clarification is needed on what "ANYPOT" refers to.

 
11. MANUAL CONFIGURATION OF HONEYPOT 

•	This is part of step 7, configuring Pentbox to define its behavior, the services it emulates, and how it interacts with attackers.
 

12. GIVING PORT 

•	Configure the ports that the honeypot services will listen on (e.g., port 22 for SSH, port 23 for Telnet).

 
13. SPECIFYING AND CONFIGUATION IF HONEYPOT BEFORE DEPLOYMENT 

•	This encompasses steps 7, 9, and 10: Setting up Pentbox's services, ports, and other settings before it's put into operation.
 
14. ATTACK

•	Simulate an attack from a separate system to test the honeypot and Snort. This could involve using tools like Nmap, Metasploit, or manual attempts to connect to the honeypot services.

15. AFTER DEPLOYMENT ATTACK

•	This is the same as step 12, attacking the honeypot to see if it works.

16. CAPTURE IN HONEYPOT AND FOUND IP OF ATTACKER

•	Verify that the honeypot (Pentbox) logs the attacker's activity, including their IP address.
•	Also, verify that Snort detects the attack and generates an alert.

 
# Result : Honeypot and IDS (Snort)
We enhanced its defence against cyberattacks by integrating a honeypot and Intrusion Detection System (IDS). This integration provides proactive threat detection, detailed attack intelligence, improved incident response, and a cost-effective security enhancement by leveraging open-source tools.
•	A dedicated Ubuntu system with Snort IDS for active network traffic monitoring.
•	A separate Debian system with Pentbox honeypot, emulating services on an isolated segment to attract and log attackers.
•	Integrated threat detection: Snort detects attacks on the honeypot, and Pentbox logs attacker details.
•	System testing confirms successful attack attraction, logging, and Snort alerting.


