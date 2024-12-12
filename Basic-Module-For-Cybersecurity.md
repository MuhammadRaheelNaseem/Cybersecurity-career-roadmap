## **🔰 Basic Module**

### **1. Fundamentals Samajhna**
#### **a. Networking Basics**
- **Topics:**
  - **TCP/IP Model:**
    - **Layers:** Application, Transport, Internet, Network Access.
    - **Protocols:** HTTP, HTTPS, FTP, SMTP, DNS.
    - **Concepts:** IP addressing, subnetting, NAT.
  - **DNS (Domain Name System):**
    - **Function:** Domain to IP resolution.
    - **Types:** Recursive, Iterative queries.
    - **Security:** DNSSEC basics.
  - **HTTP/HTTPS:**
    - **Difference:** Encryption in HTTPS.
    - **Methods:** GET, POST, PUT, DELETE.
    - **Status Codes:** 200, 404, 500, etc.
  - **Subnetting:**
    - **Calculations:** CIDR notation, subnet masks.
    - **Practice:** Create subnets for given IP ranges.
  - **Routing and Switching:**
    - **Devices:** Routers vs. Switches.
    - **Protocols:** OSPF, BGP, VLANs.
    - **Concepts:** Routing tables, MAC addressing.
  - **OSI Model:**
    - **Layers:** Physical, Data Link, Network, Transport, Session, Presentation, Application.
    - **Functions:** Understanding what each layer does.
    - **Examples:** Mapping protocols to OSI layers.
  
- **Resources:**
  - **Books:** 
    - "Computer Networking: A Top-Down Approach" by James Kurose & Keith Ross
    - "Networking All-in-One For Dummies" by Doug Lowe
  - **Courses:** 
    - **Cisco CCNA:** 
      - **Platforms:** [Coursera](https://www.coursera.org/), [Udemy](https://www.udemy.com/)
      - **Content:** Comprehensive networking fundamentals, exam preparation.
    - **CompTIA Network+:** 
      - **Platforms:** [edX](https://www.edx.org/), [LinkedIn Learning](https://www.linkedin.com/learning/)
      - **Content:** Broad networking knowledge, vendor-neutral.
  - **Websites:**
    - **Cisco Networking Academy:** [Cisco NetAcad](https://www.netacad.com/)
    - **FreeCodeCamp Networking Tutorials:** [FreeCodeCamp](https://www.freecodecamp.org/)

- **Practical Steps:**
  - **Set Up a Home Network Lab:**
    - **Tools:** Use VirtualBox or VMware to create virtual networks.
    - **Exercises:** Configure IP addresses, set up basic routers and switches using simulation tools like Cisco Packet Tracer or GNS3.
  - **Hands-On Practice:**
    - **Subnetting Exercises:** Use online subnet calculators and practice manually.
    - **Packet Analysis:** Use Wireshark to capture and analyze network traffic.

#### **b. Operating Systems**
- **Topics:**
  - **Windows OS Fundamentals:**
    - **Installation:** Install different versions (e.g., Windows 10, Windows Server).
    - **Administration:** User management, file permissions, system settings.
    - **Security Features:** Windows Defender, Firewall settings.
  - **Linux Basics (Focus on Kali Linux):**
    - **Installation:** Install Kali Linux in a virtual machine.
    - **Command Line Usage:**
      - **Basic Commands:** ls, cd, mkdir, rm, cp, mv.
      - **File Permissions:** chmod, chown.
      - **Package Management:** apt-get, yum.
    - **Security Tools:** Introduction to tools like Nmap, Metasploit, Wireshark.
  - **Command Line Usage:**
    - **Windows:** PowerShell basics, Command Prompt commands.
    - **Linux:** Shell scripting basics, navigating the file system.
    - **Comparisons:** Understanding differences between Windows and Linux command lines.
  
- **Resources:**
  - **Books:** 
    - "The Linux Command Line" by William Shotts
    - "Windows 10 for Dummies" by Andy Rathbone
  - **Courses:** 
    - **Linux Essentials:** 
      - **Platforms:** [edX](https://www.edx.org/), [Coursera](https://www.coursera.org/)
      - **Content:** Basic Linux commands, file system navigation, shell scripting.
    - **Windows Administration:**
      - **Platforms:** [Udemy](https://www.udemy.com/), [LinkedIn Learning](https://www.linkedin.com/learning/)
      - **Content:** User and group management, system settings, security configurations.
  - **Practice:**
    - **Virtual Machines:** 
      - **Tools:** VirtualBox, VMware.
      - **Tasks:** Install both Windows and Linux, practice switching between them, perform basic administrative tasks.
    - **Hands-On Projects:**
      - **Windows:** Set up user accounts, configure firewall rules.
      - **Linux:** Create and manage files/directories, write simple shell scripts.

- **Practical Steps:**
  - **Daily Command Line Practice:**
    - **Windows:** Use PowerShell daily for tasks like file management and system monitoring.
    - **Linux:** Navigate directories, manage files, and execute basic commands regularly.
  - **Set Up Dual Boot or Use Virtual Machines:**
    - **Benefits:** Experience both operating systems without needing separate hardware.
    - **Exercises:** Install software, configure settings, and troubleshoot common issues on both OS.

### **2. Programming Languages Seekhna**
#### **a. Python**
- **Topics:**
  - **Syntax and Basic Programming Concepts:**
    - **Variables and Data Types:** Strings, integers, floats, lists, dictionaries.
    - **Control Structures:** If-else statements, loops (for, while).
    - **Functions:** Defining and calling functions, scope, arguments.
    - **Error Handling:** Try-except blocks, handling exceptions.
  - **Scripting and Automation:**
    - **Automate Tasks:** File manipulation, data scraping.
    - **Libraries:** os, sys, shutil for file operations.
    - **Examples:** Write scripts to automate repetitive tasks like renaming files or organizing directories.
  - **Introduction to Libraries (e.g., Scapy, Requests):**
    - **Scapy:** Network packet manipulation and analysis.
    - **Requests:** Making HTTP requests for web interactions.
    - **Practical Use Cases:** Building simple network scanners, interacting with web APIs.
  
- **Resources:**
  - **Books:** 
    - "Automate the Boring Stuff with Python" by Al Sweigart
    - "Python Crash Course" by Eric Matthes
  - **Courses:** 
    - **Codecademy Python Course:** Interactive learning with hands-on exercises. [Codecademy](https://www.codecademy.com/)
    - **Coursera Python for Everybody:** Comprehensive course covering basics to advanced topics. [Coursera](https://www.coursera.org/specializations/python)
    - **edX Introduction to Python:** University-level introduction. [edX](https://www.edx.org/)
  - **Websites:**
    - **Real Python:** Tutorials and articles. [Real Python](https://realpython.com/)
    - **W3Schools Python Tutorial:** Beginner-friendly tutorials. [W3Schools](https://www.w3schools.com/python/)
  
- **Practical Steps:**
  - **Daily Coding Practice:**
    - **Exercises:** Solve problems on platforms like [LeetCode](https://leetcode.com/), [HackerRank](https://www.hackerrank.com/domains/tutorials/10-days-of-python).
    - **Projects:** Build simple projects like a calculator, to-do list app, or a basic web scraper.
  - **Build Security Tools:**
    - **Examples:** Create a basic port scanner, write scripts to automate vulnerability scans.
    - **Practice:** Use Scapy to craft and send custom packets, analyze responses.

#### **b. Bash/Shell Scripting**
- **Topics:**
  - **Basic Shell Commands:**
    - **Navigation:** cd, ls, pwd.
    - **File Operations:** cp, mv, rm, mkdir, rmdir.
    - **Viewing Files:** cat, less, head, tail.
  - **Writing and Executing Shell Scripts:**
    - **Script Structure:** Shebang (`#!/bin/bash`), comments, executable permissions.
    - **Variables and Parameters:** Using and manipulating variables.
    - **Control Structures:** If-else, for loops, while loops.
    - **Functions:** Defining and using functions within scripts.
  - **Automation Tasks in Linux:**
    - **Scheduled Tasks:** Using cron jobs to schedule scripts.
    - **System Monitoring:** Writing scripts to monitor system resources.
    - **Backup Scripts:** Automate backup of important files and directories.
  
- **Resources:**
  - **Courses:** 
    - **Udemy Linux Shell Scripting:** Comprehensive course covering basics to advanced scripting. [Udemy](https://www.udemy.com/course/linux-shell-scripting/)
    - **LinkedIn Learning:** Various courses on shell scripting. [LinkedIn Learning](https://www.linkedin.com/learning/)
  - **Websites:**
    - **Shell Scripting Tutorial:** Detailed tutorials and examples. [ShellScript.sh](https://www.shellscript.sh/)
    - **TutorialsPoint Shell Scripting:** Beginner-friendly guides. [TutorialsPoint](https://www.tutorialspoint.com/unix/shell_scripting.htm)
  - **Books:** 
    - "Learning the bash Shell" by Cameron Newham
    - "Shell Scripting: Expert Recipes for Linux, Bash and more" by Steve Parker
  
- **Practical Steps:**
  - **Write Daily Scripts:**
    - **Examples:** Create a script to clean up temporary files, automate software updates, or manage user accounts.
  - **Automate Common Tasks:**
    - **Backup Automation:** Schedule a script to back up important directories daily.
    - **System Monitoring:** Write scripts to log system performance metrics.
  - **Practice with Real-World Scenarios:**
    - **Scenario 1:** Automate the deployment of a web server.
    - **Scenario 2:** Write a script to parse log files and extract useful information.

### **3. Basic Cybersecurity Concepts**
- **Topics:**
  - **CIA Triad (Confidentiality, Integrity, Availability):**
    - **Confidentiality:** Ensuring information is accessible only to those authorized.
    - **Integrity:** Maintaining the accuracy and completeness of data.
    - **Availability:** Ensuring reliable access to information and resources.
  - **Types of Threats and Vulnerabilities:**
    - **Threats:** Malware, phishing, insider threats, DDoS attacks.
    - **Vulnerabilities:** Software bugs, misconfigurations, weak passwords.
    - **Exploits:** Techniques used to take advantage of vulnerabilities.
  - **Basics of Encryption, Authentication, and Authorization:**
    - **Encryption:** Symmetric vs. asymmetric encryption, common algorithms (AES, RSA).
    - **Authentication:** Methods (passwords, biometrics, multi-factor authentication).
    - **Authorization:** Access control models (RBAC, ABAC).
  - **Additional Concepts:**
    - **Security Policies:** Importance and examples of security policies.
    - **Risk Management:** Identifying, assessing, and mitigating risks.
    - **Security Frameworks:** Overview of NIST, ISO 27001.
  
- **Resources:**
  - **Books:** 
    - "Cybersecurity Essentials" by Charles J. Brooks
    - "Security+ Guide to Network Security Fundamentals" by Mark Ciampa
  - **Courses:** 
    - **Introduction to Cyber Security (Coursera):** Basics of cybersecurity concepts and practices. [Coursera](https://www.coursera.org/)
    - **edX Cyber Security Fundamentals:** Comprehensive introduction to cybersecurity. [edX](https://www.edx.org/)
    - **Cybrary Intro to IT & Cybersecurity:** Free and structured learning path. [Cybrary](https://www.cybrary.it/)
  - **Websites:**
    - **Khan Academy:** Basic cryptography courses. [Khan Academy](https://www.khanacademy.org/)
    - **OWASP:** Learn about common web vulnerabilities. [OWASP](https://owasp.org/)
  
- **Practical Steps:**
  - **Case Studies Analysis:**
    - **Examples:** Analyze recent cybersecurity breaches to understand how CIA triad was compromised.
  - **Hands-On Encryption:**
    - **Exercises:** Encrypt and decrypt files using tools like OpenSSL.
  - **Create Security Policies:**
    - **Task:** Draft a basic security policy for a hypothetical organization, covering areas like password policies, data protection, and incident response.

### **4. Introductory Certifications**
- **Certifications:**
  - **CompTIA IT Fundamentals (ITF+):**
    - **Purpose:** Provides a basic understanding of IT concepts, ideal for beginners.
    - **Topics Covered:** IT literacy, infrastructure, applications, software development.
    - **Benefits:** Validates foundational IT knowledge, a stepping stone to more advanced certifications.
  - **CompTIA Security+:**
    - **Purpose:** Entry-level certification focused on foundational cybersecurity skills.
    - **Topics Covered:** Threats, vulnerabilities, network security, cryptography, identity management.
    - **Benefits:** Widely recognized, improves job prospects, prerequisite for advanced certifications.
  
- **Resources:**
  - **Books:** 
    - "CompTIA Security+ Study Guide" by Mike Chapple and David Seidl
    - "CompTIA IT Fundamentals (ITF+) Study Guide" by Quentin Docter
  - **Courses:** 
    - **Udemy CompTIA Security+:** Comprehensive courses with practice exams. [Udemy](https://www.udemy.com/)
    - **LinkedIn Learning:** Structured learning paths for ITF+ and Security+. [LinkedIn Learning](https://www.linkedin.com/learning/)
    - **CompTIA Official Training:** Official materials and online training from CompTIA. [CompTIA](https://www.comptia.org/)
  - **Practice Exams:**
    - **ExamSim:** Simulated exams to prepare for the real test. [ExamSim](https://www.examsim.com/)
    - **Professor Messer’s Free Resources:** [Professor Messer](https://www.professormesser.com/)
  
- **Practical Steps:**
  - **Create a Study Schedule:**
    - **Plan:** Allocate specific hours each day/week for studying.
    - **Goals:** Set milestones for completing chapters, practicing questions, and taking mock exams.
  - **Join Study Groups:**
    - **Platforms:** Reddit r/CompTIA, Discord study channels.
    - **Benefits:** Peer support, shared resources, discussion of difficult topics.
  - **Hands-On Labs:**
    - **Tools:** Use virtual labs to apply theoretical knowledge.
    - **Exercises:** Configure firewalls, set up encryption, practice incident response scenarios.

### **5. Practical Skills Develop Karna**
- **Activities:**
  - **Set Up a Home Lab with Virtual Machines:**
    - **Tools:** VirtualBox or VMware for creating multiple virtual environments.
    - **Components:** Install different operating systems (Windows, Linux), set up virtual networks.
    - **Exercises:** Simulate network attacks, practice defense mechanisms.
  - **Practice Basic Networking and OS Commands:**
    - **Networking:** Configure IP addresses, set up DHCP and DNS servers in the virtual lab.
    - **OS Commands:** Regularly use command line interfaces to manage systems.
  - **Start Small Projects Like Building Simple Scripts for Automation:**
    - **Examples:**
      - **Python Script:** Automate the backup of important files.
      - **Bash Script:** Monitor system resources and alert when thresholds are exceeded.
      - **Project Ideas:** Create a simple port scanner, develop a basic intrusion detection system.
  
- **Resources:**
  - **Online Labs:**
    - **TryHackMe:** Interactive learning with guided labs. [TryHackMe](https://tryhackme.com/)
    - **Hack The Box:** Penetration testing labs and challenges. [Hack The Box](https://www.hackthebox.com/)
  - **Books:**
    - "The Practice of System and Network Administration" by Thomas A. Limoncelli
    - "Automate the Boring Stuff with Python" by Al Sweigart
  - **Websites:**
    - **OverTheWire:** Wargames to practice security concepts. [OverTheWire](https://overthewire.org/)
    - **Cuckoo Sandbox:** Practice malware analysis. [Cuckoo Sandbox](https://cuckoosandbox.org/)
  
- **Practical Steps:**
  - **Build and Secure a Virtual Network:**
    - **Setup:** Create multiple virtual machines to simulate a network.
    - **Exercises:** Implement firewall rules, set up VPNs, practice securing services.
  - **Develop and Test Scripts:**
    - **Python:** Write scripts to automate network scans, log analysis.
    - **Bash:** Create scripts for system maintenance tasks like clearing logs, updating software.
  - **Participate in CTF Challenges:**
    - **Platforms:** [TryHackMe](https://tryhackme.com/), [Hack The Box](https://www.hackthebox.com/), [OverTheWire](https://overthewire.org/)
    - **Benefits:** Apply theoretical knowledge in practical scenarios, improve problem-solving skills.

---

## **📅 Detailed Timeline for Basic Module (Approx. 6-12 Months)**

### **Months 1-3: Fundamentals Samajhna**
- **Networking Basics:**
  - **Weeks 1-4:** Study TCP/IP, DNS, HTTP/HTTPS.
  - **Weeks 5-8:** Learn subnetting, routing, switching.
  - **Weeks 9-12:** Understand OSI Model, set up virtual networks using Cisco Packet Tracer or GNS3.
- **Operating Systems:**
  - **Weeks 1-6:** Install and explore Windows OS, perform basic administration tasks.
  - **Weeks 7-12:** Install Kali Linux, learn basic Linux commands, set up a dual-boot or virtual machine environment.

### **Months 4-6: Programming Languages Seekhna**
- **Python:**
  - **Weeks 13-18:** Complete Python basics (variables, data types, control structures).
  - **Weeks 19-24:** Learn scripting and automation, start using libraries like Scapy and Requests.
- **Bash/Shell Scripting:**
  - **Weeks 19-24:** Learn basic shell commands, write simple scripts for automation tasks.
  - **Weeks 25-26:** Implement scripts in the home lab environment.

### **Months 7-9: Basic Cybersecurity Concepts & Intro Certifications**
- **Basic Cybersecurity Concepts:**
  - **Weeks 25-30:** Study CIA Triad, types of threats and vulnerabilities.
  - **Weeks 31-36:** Learn basics of encryption, authentication, and authorization.
- **Introductory Certifications:**
  - **Weeks 25-36:** Prepare for CompTIA Security+ exam using study guides and online courses.
  - **Weeks 37-40:** Schedule and take the CompTIA Security+ exam.

### **Months 10-12: Practical Skills Develop Karna**
- **Set Up a Home Lab:**
  - **Weeks 37-40:** Finalize the home lab setup, install necessary tools and software.
- **Practice Networking and OS Commands:**
  - **Weeks 41-44:** Regularly practice commands, configure network settings.
- **Start Small Projects:**
  - **Weeks 45-52:** Develop simple automation scripts, participate in basic CTF challenges.

---

## **✅ Final Tips for Basic Level**

- **Consistency:** Dedicate a little time every day to study and practice.  
- **Hands-On Practice:** Always focus on practical application along with theory.  
- **Stay Organized:** Stick to your study schedule, set milestones, and work to achieve them.  
- **Seek Help When Needed:** If you face issues with any topic, seek help from online forums or study groups.  
- **Document Your Learning:** Keep records of your projects, scripts, and lab setups to build your portfolio.  
