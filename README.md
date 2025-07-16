# auditlock

AuditLock is a desktop application written in C++ using the Qt5 framework, designed to perform security audits on Linux systems. It acts as a "security scanner" that checks for common vulnerabilities and misconfigurations. The application provides a graphical user interface (GUI) to initiate scans, display real-time progress and logs, and generate reports.  

Note: This is not a system hardening tool.  There are other opensource applications that do that work.  This code is here only for educational purposes only.

Key features and functionalities include:

Full System Audit: Comprehensive scan covering various security aspects.

Modular Security Checks: Ability to perform individual checks for:

Password Policy: Audits /etc/login.defs for password minimum length, maximum days, and minimum days between changes.

Kernel Parameters (Sysctl): Verifies critical kernel parameters related to networking and memory randomization (ASLR).

Outdated Packages: Checks for available package updates using apt to ensure the system has the latest security patches.

SSH Configuration: Inspects sshd_config for insecure root login settings.

SUID/SGID Files: Scans the file system for Set User ID (SUID) and Set Group ID (SGID) executables, highlighting potentially risky ones.

World-Writable Files: Identifies files and directories that are writable by all users, which can be a significant security risk.

Network Ports: Lists listening TCP/UDP ports and associated processes using lsof.

Firewall Status: Checks if UFW or Firewalld is active and configured securely.

Interactive Log View: Displays audit results with color-coded messages (good, info, risky, danger) and supports filtering to easily review specific types of findings.

Progress Tracking: A progress bar indicates the scan's advancement.

Report Generation: Allows saving the audit results to a text file or copying them to the clipboard.

Privilege Handling: Uses pkexec for commands requiring elevated privileges, ensuring secure execution.

AuditLock aims to provide an easy-to-use tool for system administrators and users to assess and improve the security posture of their Linux machines.


General Disclaimer:

AuditLock is provided "as is," without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software. 

Specific Disclaimers:

Not a Comprehensive Security Solution: AuditLock is a tool designed to assist in identifying common security vulnerabilities and misconfigurations. It is 

not a substitute for a comprehensive security strategy, regular professional security audits, or adherence to best security practices. 

False Positives/Negatives: While efforts have been made to ensure accuracy, AuditLock may produce false positives (flagging benign items as issues) or false negatives (failing to identify actual vulnerabilities). Users should independently verify all findings. 


System Impact: Some checks performed by AuditLock, particularly those requiring package updates (e.g., apt update), may require internet access and can temporarily consume system resources. 

Privileged Operations: Certain scans require elevated privileges (e.g., using pkexec). Users are responsible for understanding the implications of granting such permissions and ensuring they trust the application. Improper use of privileged commands can lead to system instability or security risks. 

Configuration Dependency: The effectiveness of AuditLock depends heavily on the specific configuration of the audited system and the presence of necessary tools (e.g., lsof, ufw, firewall-cmd, apt, sysctl). Missing tools or unusual system setups may lead to incomplete or inaccurate results. 

No Guarantee of Security: Running AuditLock does not guarantee that your system is completely secure or immune to all forms of attack. New vulnerabilities are discovered daily, and effective security requires continuous vigilance and updates. 

User Responsibility: Users are solely responsible for any actions taken based on the results or recommendations provided by AuditLock. It is strongly advised to back up critical data and understand the potential impact of any configuration changes before implementing them. 


Development Status: This software is provided as a development version (Version: 1)  and may contain bugs or incomplete features. Future versions may introduce changes in functionality or reporting
