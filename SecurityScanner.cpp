#include "SecurityScanner.h"
#include <QFile>
#include <QTextStream>
#include <sys/stat.h> // For stat() system call
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <QDebug> // For qWarning()
#include <QCoreApplication> // Needed for QCoreApplication::processEvents()
#include <errno.h> // For errno (system error number)
#include <string.h> // For strerror (converts errno to string)
#include <QRegularExpression> // Essential for QRegularExpression and QRegularExpressionMatch
#include <QRegularExpressionMatch> // Essential for QRegularExpression and QRegularExpressionMatch


SecurityScanner::SecurityScanner(QObject *parent) : QThread(parent) {}

// Public methods to trigger specific scans (these start the QThread)
void SecurityScanner::startFullAudit() {
    _runFullAudit = true;
    _runPasswordPolicyCheck = false;
    _runKernelParamsCheck = false;
    _runOutdatedPackagesCheck = false;
    start(); // QThread::start()
}

void SecurityScanner::checkPasswordPolicy() {
    _runPasswordPolicyCheck = true;
    _runFullAudit = false;
    _runKernelParamsCheck = false;
    _runOutdatedPackagesCheck = false;
    start();
}

void SecurityScanner::checkKernelParams() {
    _runKernelParamsCheck = true;
    _runFullAudit = false;
    _runPasswordPolicyCheck = false;
    _runOutdatedPackagesCheck = false;
    start();
}

void SecurityScanner::checkOutdatedPackages() {
    _runOutdatedPackagesCheck = true;
    _runFullAudit = false;
    _runPasswordPolicyCheck = false;
    _runKernelParamsCheck = false;
    start();
}

// Helper function to execute a command and return its stdout and stderr
QPair<QString, QString> SecurityScanner::executeCommand(const QString &command) {
    QProcess process;
    process.start("sh", QStringList() << "-c" << command);
    process.waitForFinished();
    QString stdOut = process.readAllStandardOutput().trimmed();
    QString stdErr = process.readAllStandardError().trimmed();

    // Exit code 0 is success. Exit code 1 can often mean "no match" or "not found" (e.g., from grep, apt list --upgradable when no upgrades).
    // We only treat other non-zero exit codes as genuine command failures.
    if (process.exitCode() != 0 && process.exitCode() != 1) {
        qWarning() << "Command failed:" << command << "Exit code:" << process.exitCode() << "Error:" << stdErr;
        // Indicate failure by returning empty stdout if exit code is genuinely an error
        return qMakePair(QString(), stdErr);
    }
    return qMakePair(stdOut, stdErr);
}

// Helper function for executing commands that require elevated privileges via pkexec
QPair<QString, QString> SecurityScanner::executePrivilegedCommand(const QString &command) {
    QProcess process;
    // pkexec itself might prompt for a graphical password. waitForFinished(-1) waits indefinitely.
    process.start("pkexec", QStringList() << "sh" << "-c" << command);
    process.waitForFinished(-1); // Wait indefinitely for user interaction or command completion

    QString stdOut = process.readAllStandardOutput().trimmed();
    QString stdErr = process.readAllStandardError().trimmed();

    if (process.exitCode() != 0 && process.exitCode() != 1) {
        qWarning() << "Privileged command failed:" << command << "Exit code:" << process.exitCode() << "Error:" << stdErr;
        return qMakePair(QString(), stdErr); // Indicate failure
    }
    return qMakePair(stdOut, stdErr);
}

// The main thread run loop - dispatches based on which audit was triggered
void SecurityScanner::run() {
    bool allGood = true; // Overall security status for the triggered audit
    QStringList issues; // List of specific issues found

    emit logMessage("Starting LockAudit system scan...\n", "info");

    if (_runFullAudit) {
        emit logMessage("Initiating Full System Audit.", "info");

        // --- Progress Setup for Full Audit ---
        // We'll use a 0-100% scale for overall progress.
        // Each major phase gets a percentage slice.
        int total_major_phases = 8; // SSH, SUID, WW, Ports, Firewall, Pass, Kernel, Packages
        int current_major_phase_index = 0;
        emit setMaxProgress(100); // Progress bar goes from 0 to 100%

        // Lambda to update overall progress (called after each major phase)
        auto updateMainProgress = [&]() {
            current_major_phase_index++;
            emit scanProgress(static_cast<int>((current_major_phase_index / static_cast<double>(total_major_phases)) * 100));
            // No processEvents here, as emitting signals across threads is handled by Qt's event loop
        };
        // -------------------------------------

        // --- SECTION HEADER ---
        emit logMessage("\n--- SSH Configuration ---\n", "section_header");
        _checkSshRootLogin(allGood, issues);
        updateMainProgress();

        // --- SECTION HEADER ---
        emit logMessage("\n--- SUID/SGID Files Scan ---\n", "section_header");
        emit logMessage("\nScanning for SUID/SGID files (could take a while)...\n", "info");
        QStringList safeSuid = {
            "/usr/bin/passwd", "/usr/bin/sudo", "/usr/bin/chsh", "/usr/bin/chfn",
            "/usr/bin/mount", "/usr/bin/umount", "/usr/bin/su", "/usr/bin/newgrp",
            "/usr/bin/gpasswd", "/usr/bin/pkexec", "/usr/bin/fusermount3",
            "/usr/lib/dbus-1.0/dbus-daemon-launch-helper", "/usr/lib/openssh/ssh-keysign",
            "/usr/lib/policykit-1/polkit-agent-helper-1",
            "/usr/libexec/polkit-agent-helper-1",
            "/usr/sbin/mount.cifs", "/usr/sbin/pppd",
            "/usr/lib/snapd/snap-confine",
            "/usr/lib/xorg/Xorg.wrap",
            "/usr/share/code/chrome-sandbox",
            "/usr/share/discord/chrome-sandbox"
        };
        // For recursive file system scans, use a separate, larger progress counter
        int suid_ww_progress_counter = 0;
        emit setMaxProgress(50000); // Estimate a large number of files/dirs for SUID/WW combined
        _scanSuid("/", safeSuid, allGood, issues, suid_ww_progress_counter);
        updateMainProgress(); // Mark SUID phase as done

        // --- SECTION HEADER ---
        emit logMessage("\n--- World-Writable Files Scan ---\n", "section_header");
        emit logMessage("\nChecking for world-writable files in /etc, /root, /var (excluding common safe ones)...\n", "info");
        _scanWorldWritable(QDir("/"), // Start from root for a comprehensive WW scan
                           { "/tmp", "/var/tmp", "/dev/shm", "/var/crash", "/var/lock", "/var/run/lock" },
                           allGood, issues, suid_ww_progress_counter); // Continues counter from SUID scan
        emit setMaxProgress(100); // Reset max progress for next phase based on overall percentage
        updateMainProgress(); // Mark World-Writable phase as done

        // --- SECTION HEADER ---
        emit logMessage("\n--- Network Ports ---\n", "section_header");
        _scanPorts(allGood, issues);
        updateMainProgress();

        // --- SECTION HEADER ---
        emit logMessage("\n--- Firewall Status ---\n", "section_header");
        _checkFirewall(allGood, issues);
        updateMainProgress();

        // --- SECTION HEADER ---
        emit logMessage("\n--- Password Policy ---\n", "section_header");
        _checkPasswordPolicy(allGood, issues);
        updateMainProgress();

        // --- SECTION HEADER ---
        emit logMessage("\n--- Kernel Parameters (Sysctl) ---\n", "section_header");
        _checkKernelParams(allGood, issues);
        updateMainProgress();

        // --- SECTION HEADER ---
        emit logMessage("\n--- Outdated Packages ---\n", "section_header");
        _checkOutdatedPackages(allGood, issues);
        updateMainProgress(); // Mark Outdated Packages phase as done

    } else if (_runPasswordPolicyCheck) {
        emit setMaxProgress(1); // Single check, quick complete (progress from 0 to 1)
        emit logMessage("Initiating Password Policy Audit.", "info");
        // --- SECTION HEADER ---
        emit logMessage("\n--- Password Policy ---\n", "section_header");
        _checkPasswordPolicy(allGood, issues); // Call the dedicated private function
        emit scanProgress(1); // Indicate completion
    } else if (_runKernelParamsCheck) {
        emit setMaxProgress(1);
        emit logMessage("Initiating Kernel Parameters (Sysctl) Audit.", "info");
        // --- SECTION HEADER ---
        emit logMessage("\n--- Kernel Parameters (Sysctl) ---\n", "section_header");
        _checkKernelParams(allGood, issues);
        emit scanProgress(1);
    } else if (_runOutdatedPackagesCheck) {
        emit setMaxProgress(1);
        emit logMessage("Initiating Outdated Packages Audit (requires 'apt' and internet access).", "info");
        // --- SECTION HEADER ---
        emit logMessage("\n--- Outdated Packages ---\n", "section_header");
        _checkOutdatedPackages(allGood, issues);
        emit scanProgress(1);
    } else {
        // Fallback for unexpected calls to run() without a flag
        emit logMessage("[WARNING] No specific audit task was triggered. Please select an option from the menu.", "risky");
        emit setMaxProgress(1); // Set progress bar to 100% (finished)
        emit scanProgress(1);
    }

    emit logMessage("\nLockAudit scan complete.", "info");
    emit scanComplete(allGood, issues); // Signal completion of the overall scan
}

// --- Private Helper Functions for Core Audit Phases ---

void SecurityScanner::_checkSshRootLogin(bool &allGood, QStringList &issues) {
    emit logMessage("Checking SSH root login status...", "info");
    QFile sshd("/etc/ssh/sshd_config");
    if (sshd.open(QIODevice::ReadOnly)) {
        QTextStream in(&sshd);
        bool rootLoginPermitted = false;
        while (!in.atEnd()) {
            QString line = in.readLine().trimmed();
            if (line.startsWith("#") || line.isEmpty()) continue; // Ignore comments and empty lines
            if (line.startsWith("PermitRootLogin", Qt::CaseInsensitive)) {
                // Check for forms that allow root login
                if (line.contains("yes", Qt::CaseInsensitive) ||
                    line.contains("without-password", Qt::CaseInsensitive) ||
                    line.contains("prohibit-password", Qt::CaseInsensitive)) {
                    rootLoginPermitted = true;
                    break;
                }
            }
        }
        sshd.close();

        if (rootLoginPermitted) {
            emit logMessage("[DANGEROUS] SSH root login is enabled. This is a security risk.", "danger");
            issues << "SSH root login enabled";
            allGood = false;
            // --- Actionable Recommendation ---
            emit logMessage("  Recommendation: Edit /etc/ssh/sshd_config and change 'PermitRootLogin yes' to 'PermitRootLogin no' (or 'without-password', 'prohibit-password' if necessary for specific setups) and restart sshd service (e.g., sudo systemctl restart sshd). Use 'sudo' for administrative tasks via a regular user account.", "info");
            // ---------------------------------
        } else {
            emit logMessage("[GOOD] SSH root login is disabled or restricted.", "good");
        }
    } else {
        // More specific error message using QFile::errorString()
        emit logMessage(QString("[INFO] Could not open /etc/ssh/sshd_config. Error: %1").arg(sshd.errorString()), "info");
    }
}

void SecurityScanner::_scanSuid(const QString &path, const QStringList &safeSuid, bool &allGood, QStringList &issues, int &progress_counter) {
    // Directories to skip during recursive scan to avoid pseudo-filesystems, loops, or irrelevant SUIDs
    QStringList skipDirs = {
        "/proc", "/sys", "/dev", "/run", "/var/run", "/tmp", "/var/tmp",
        "/snap", // Snap mounts many SUID/SGID files in read-only mounts, which are legitimate
        "/var/lib/snapd/snaps", // Also part of snap system
        "/home", // Users should not typically have SUID files in their home directories
        "/media", "/mnt" // Removable media mount points
    };

    QDir dir(path);
    // Get list of directories and files, excluding '.' and '..'
    QFileInfoList list = dir.entryInfoList(QDir::Dirs | QDir::Files | QDir::NoDotAndDotDot);
    for (const QFileInfo &fi : list) {
        QString absolutePath = fi.absoluteFilePath();

        if (fi.isDir()) {
            bool skip = false;
            for (const QString &skipDir : skipDirs) {
                // Check if the current directory is one of the skip directories or starts with one
                if (absolutePath == skipDir || absolutePath.startsWith(skipDir + "/")) {
                    skip = true;
                    break;
                }
            }
            if (!skip) {
                // Recurse into subdirectories
                _scanSuid(absolutePath, safeSuid, allGood, issues, progress_counter);
            }
        } else if (fi.isFile()) {
            progress_counter++; // Increment counter for each file processed
            if (progress_counter % 500 == 0) { // Emit progress every 500 files/dirs
                emit scanProgress(progress_counter);
                QCoreApplication::processEvents(); // Keep UI responsive during long scans
            }
            struct stat st;
            // Use stat() to get file status (permissions, ownership, etc.)
            if (stat(absolutePath.toStdString().c_str(), &st) == 0) {
                // Check for SUID (Set User ID) or SGID (Set Group ID) bits
                if ((st.st_mode & S_ISUID) || (st.st_mode & S_ISGID)) {
                    if (safeSuid.contains(absolutePath)) {
                        emit logMessage(QString("[GOOD] SUID/SGID file: %1 (OK)").arg(absolutePath), "good");
                    } else {
                        // Special handling for browser/Electron app sandboxes (legitimate SUID/SGID)
                        if (absolutePath.contains("chrome-sandbox", Qt::CaseInsensitive) ||
                            absolutePath.contains("electron", Qt::CaseInsensitive)) {
                            emit logMessage(QString("[INFO] SUID/SGID sandbox: %1 (Common for browsers/Electron apps)").arg(absolutePath), "info");
                        } else {
                            emit logMessage(QString("[RISKY] SUID/SGID file: %1 (Review if necessary)").arg(absolutePath), "risky");
                            issues << QString("SUID/SGID: %1").arg(absolutePath);
                            allGood = false;
                            // --- Actionable Recommendation ---
                            emit logMessage(QString("  Recommendation: Verify this SUID/SGID file is legitimate and from a trusted source. If unsure or unneeded, consider removing the associated package (e.g., sudo apt remove <package-name>). Check if it's a known vulnerability source for privilege escalation."), "info");
                            // ---------------------------------
                        }
                    }
                }
            } else {
                // More specific stat() error message using strerror(errno)
                emit logMessage(QString("[INFO] Cannot stat file '%1' (Error: %2)").arg(absolutePath).arg(strerror(errno)), "info");
            }
        }
    }
}

void SecurityScanner::_scanWorldWritable(const QDir &dir, const QStringList &stickyBitOkPaths, bool &allGood, QStringList &issues, int &progress_counter) {
    QFileInfoList list = dir.entryInfoList(QDir::Files | QDir::Dirs | QDir::NoDotAndDotDot);
    for (const QFileInfo &fi : list) {
        QString absolutePath = fi.absoluteFilePath();
        struct stat st;

        if (absolutePath.startsWith("/proc") || absolutePath.startsWith("/sys") ||
            absolutePath.startsWith("/dev") || absolutePath.startsWith("/run")) {
            continue;
        }

        if (stat(absolutePath.toStdString().c_str(), &st) == 0) {
            progress_counter++; // Increment counter for each item (file or dir) processed
            if (progress_counter % 500 == 0) { // Emit progress every 500 items
                emit scanProgress(progress_counter);
                QCoreApplication::processEvents(); // Keep UI responsive
            }

            if (st.st_mode & S_IWOTH) { // If world-writable bit is set
                bool isStickyBitSet = (st.st_mode & S_ISVTX); // Check for sticky bit (S_ISVTX)

                if (isStickyBitSet) {
                    bool isLegitSticky = false;
                    for (const QString &okPath : stickyBitOkPaths) {
                        if (absolutePath == okPath || absolutePath.startsWith(okPath + "/")) {
                            isLegitSticky = true;
                            break;
                        }
                    }
                    if (isLegitSticky) {
                        emit logMessage(QString("[GOOD] World-writable (sticky bit): %1 (Standard for temp directories)").arg(absolutePath), "good");
                    } else {
                        emit logMessage(QString("[RISKY] World-writable (sticky bit, non-standard): %1 (Review)").arg(absolutePath), "risky");
                        issues << QString("World-writable (sticky bit, non-standard): %1").arg(absolutePath);
                        allGood = false;
                        // --- Actionable Recommendation ---
                        emit logMessage(QString("  Recommendation: This directory or file is world-writable with a sticky bit, but is not a standard temporary location. Review its purpose. If unintended, remove world-write permissions (e.g., sudo chmod o-w %1).").arg(absolutePath), "info");
                        // ---------------------------------
                    }
                } else { // World-writable without sticky bit
                    if (fi.isDir()) {
                        emit logMessage(QString("[DANGER] World-writable DIRECTORY (no sticky bit): %1 (Critical Risk!)").arg(absolutePath), "danger");
                        issues << QString("World-writable DIR: %1").arg(absolutePath);
                        allGood = false;
                        // --- Actionable Recommendation ---
                        emit logMessage(QString("  Recommendation: This directory is highly insecure. Remove world-write permissions immediately (e.g., sudo chmod o-w %1 or sudo chmod 755 %1 if safe). This could allow any user to delete/create/modify files within it.").arg(absolutePath), "info");
                        // ---------------------------------
                    } else { // World-writable file
                        emit logMessage(QString("[RISKY] World-writable FILE: %1 (Review)").arg(absolutePath), "risky");
                        issues << QString("World-writable FILE: %1").arg(absolutePath);
                        allGood = false;
                        // --- Actionable Recommendation ---
                        emit logMessage(QString("  Recommendation: This file is world-writable. Remove world-write permissions unless specifically intended (e.g., sudo chmod o-w %1 or sudo chmod 644 %1 if safe). An attacker could modify its contents.").arg(absolutePath), "info");
                        // ---------------------------------
                    }
                }
            }
        } else {
            // More specific stat() error message using strerror(errno)
            emit logMessage(QString("[INFO] Cannot stat file '%1' (Error: %2)").arg(absolutePath).arg(strerror(errno)), "info");
        }

        if (fi.isDir()) {
            // Recurse into subdirectories, avoiding known problematic or irrelevant paths
            if (!absolutePath.startsWith("/proc") && !absolutePath.startsWith("/sys") &&
                !absolutePath.startsWith("/dev") && !absolutePath.startsWith("/run") &&
                !absolutePath.startsWith("/tmp") && !absolutePath.startsWith("/var/tmp") &&
                !absolutePath.startsWith("/snap") && !absolutePath.startsWith("/home") &&
                !absolutePath.startsWith("/media") && !absolutePath.startsWith("/mnt")) {
                _scanWorldWritable(QDir(absolutePath), stickyBitOkPaths, allGood, issues, progress_counter);
            }
        }
    }
}

void SecurityScanner::_scanPorts(bool &allGood, QStringList &issues) {
    emit logMessage("Checking listening TCP/UDP ports and associated processes (requires 'lsof')...\n", "info");
    QPair<QString, QString> result = executeCommand("lsof -i -P -n");
    QString lsofOutput = result.first;
    QString lsofError = result.second;

    QStringList lines = lsofOutput.split('\n', Qt::SkipEmptyParts);
    if (lsofOutput.isEmpty() || !lines.first().contains("COMMAND")) {
        emit logMessage(QString("[WARNING] 'lsof' command failed or not found. Cannot perform detailed port scan. Error: %1").arg(lsofError.isEmpty() ? "No output" : lsofError), "risky");
        issues << "Detailed port scan failed (lsof issue)";
        emit logMessage("  Recommendation: Ensure 'lsof' is installed (sudo apt install lsof) and your user has permissions to execute it. This tool is crucial for detailed port analysis.", "info");
        return;
    }

    // No specific "RISKY" or "DANGER" flags for ports here, as UFW handles blocking.
    // This section is purely informational to list what's listening internally.
    // The firewall check will determine if external access is blocked.

    for (int i = 1; i < lines.size(); ++i) {
        QString line = lines.at(i).trimmed();
        QStringList parts = line.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
        if (parts.size() < 9) continue;

        QString command = parts.at(0);
        QString pid = parts.at(1);
        QString type = parts.at(7);
        QString protocol = parts.at(8);
        QString name = parts.at(9);

        QRegularExpression re(":\\d+");
        QRegularExpressionMatch match = re.match(name);
        QString port_str;
        if (match.hasMatch()) {
            port_str = match.captured(0).mid(1);
        } else {
            continue;
        }

        emit logMessage(QString("[INFO] Open %1 Port: %2 (%3) - Process: %4 (PID: %5)").arg(protocol).arg(port_str).arg(type).arg(command).arg(pid), "info");
        // No issue added to list, as this is informational about internal listeners.
    }
}

void SecurityScanner::_checkFirewall(bool &allGood, QStringList &issues) {
    emit logMessage("\nChecking firewall status and configuration...\n", "info");
    // Use executePrivilegedCommand for ufw status verbose as it requires elevated privileges
    QPair<QString, QString> ufwResult = executePrivilegedCommand("ufw status verbose");
    QString ufwStatusVerbose = ufwResult.first;
    QString ufwError = ufwResult.second;

    if (ufwStatusVerbose.contains("Status: active", Qt::CaseInsensitive)) {
        emit logMessage("[GOOD] UFW firewall is active.", "good");

        if (!ufwStatusVerbose.contains("Default: deny (incoming)", Qt::CaseInsensitive)) {
            emit logMessage("[RISKY] UFW default incoming policy is NOT 'deny'. System is more exposed.", "risky");
            issues << "UFW default incoming policy is not 'deny'";
            allGood = false;
            emit logMessage("  Recommendation: Set UFW's default incoming policy to 'deny' (sudo ufw default deny incoming). This blocks all incoming connections by default, enhancing security. Then, add specific 'allow' rules for services you need (e.g., sudo ufw allow ssh).", "info");
        } else {
            emit logMessage("[GOOD] UFW default incoming policy is 'deny'.", "good");
        }
        if (!ufwStatusVerbose.contains("Default: allow (outgoing)", Qt::CaseInsensitive)) {
            // This is more of a configuration issue than a direct security risk, but can cause problems.
            emit logMessage("[RISKY] UFW default outgoing policy is NOT 'allow'. This may restrict your system's outbound connectivity.", "risky");
            emit logMessage("  Recommendation: Set UFW's default outgoing policy to 'allow' (sudo ufw default allow outgoing). Then, if necessary, add specific 'deny' rules for unwanted outbound connections.", "info");
        } else {
             emit logMessage("[GOOD] UFW default outgoing policy is 'allow'.", "good");
        }

    } else {
        QPair<QString, QString> firewallDResult = executeCommand("firewall-cmd --state");
        QString firewallDState = firewallDResult.first; // Corrected from firewallDDResult
        QString firewallDError = firewallDResult.second;

        if (firewallDState.contains("running", Qt::CaseInsensitive)) {
            emit logMessage("[GOOD] Firewalld is active.", "good");
            emit logMessage("  Recommendation: Ensure Firewalld is configured to only allow necessary incoming traffic. Use 'sudo firewall-cmd --list-all' to review rules and zones.", "info");
        } else {
            emit logMessage(QString("[DANGER] No active firewall detected. UFW status error: '%1'. Firewalld status error: '%2'").arg(ufwError).arg(firewallDError), "danger");
            allGood = false;
            issues << "No active firewall detected";
            emit logMessage("  Recommendation: Enable a firewall immediately. For Pop!_OS/Ubuntu, UFW is recommended (sudo ufw enable). After enabling, configure specific rules for services you need (e.g., sudo ufw allow ssh).", "info");
        }
    }
}

void SecurityScanner::_checkPasswordPolicy(bool &allGood, QStringList &issues) {
    emit logMessage("Initiating Password Policy Audit.", "info");
    QFile loginDefs("/etc/login.defs");
    if (loginDefs.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QTextStream in(&loginDefs);
        int minLen = 6;
        int maxDays = 99999;
        int minDays = 0;
        QString encryptMethod = "UNKNOWN";

        while (!in.atEnd()) {
            QString line = in.readLine().trimmed();
            if (line.startsWith("#") || line.isEmpty()) continue;

            if (line.startsWith("PASS_MIN_LEN")) {
                minLen = line.section(' ', -1).toInt();
            } else if (line.startsWith("PASS_MAX_DAYS")) {
                maxDays = line.section(' ', -1).toInt();
            } else if (line.startsWith("PASS_MIN_DAYS")) {
                minDays = line.section(' ', -1).toInt();
            } else if (line.startsWith("ENCRYPT_METHOD")) {
                encryptMethod = line.section(' ', -1);
            }
        }
        loginDefs.close();

        emit logMessage(QString("[INFO] Password Policy from /etc/login.defs:"), "info");

        // Min Length Check
        emit logMessage(QString(" - Minimum Length: %1").arg(minLen), minLen < 8 ? "risky" : "good");
        if (minLen < 8) {
            allGood = false;
            issues << "Weak password min length (" + QString::number(minLen) + " < 8)";
            emit logMessage("  Recommendation: Increase PASS_MIN_LEN to 8 or more in /etc/login.defs and ensure PAM modules (e.g., pam_cracklib.so or pam_pwquality.so) enforce strong complexity rules (e.g., sudo nano /etc/pam.d/common-password).", "info");
        }

        // Max Days Check
        emit logMessage(QString(" - Maximum Days: %1").arg(maxDays), maxDays > 180 ? "risky" : "good");
        if (maxDays > 180) {
            allGood = false;
            issues << "Password max days too long (" + QString::number(maxDays) + " > 180)";
            emit logMessage("  Recommendation: Reduce PASS_MAX_DAYS to 90-180 in /etc/login.defs to enforce regular password changes. This helps mitigate risks from compromised credentials.", "info");
        }

        // Min Days Check
        emit logMessage(QString(" - Minimum Days (change freq): %1").arg(minDays), minDays > 0 ? "good" : "risky");
        if (minDays == 0) {
            allGood = false;
            issues << "Password min days is 0 (allows immediate change)";
            emit logMessage("  Recommendation: Set PASS_MIN_DAYS to a value greater than 0 (e.g., 1) in /etc/login.defs to prevent users from immediately changing a newly set password back. This ensures a password is used for a minimum period.", "info");
        }

        emit logMessage(QString(" - Encryption Method: %1 (Requires PAM configuration check for full strength analysis)").arg(encryptMethod), "info");

    } else {
        emit logMessage(QString("[RISKY] Could not open /etc/login.defs to check password policy. Error: %1").arg(loginDefs.errorString()), "risky");
        issues << "Could not check password policy (file access error)";
        allGood = false;
        emit logMessage("  Recommendation: Verify file permissions for /etc/login.defs. It should typically be readable by all (e.g., chmod 644 /etc/login.defs).", "info");
    }
}

void SecurityScanner::_checkKernelParams(bool &allGood, QStringList &issues) {
    emit logMessage("Initiating Kernel Parameters (Sysctl) Audit.", "info");
    struct { const char* param; const char* expected; const char* description; } sysctlChecks[] = {
        {"net.ipv4.ip_forward", "0", "IP Forwarding (should be 0 for desktop systems)"},
        {"kernel.randomize_va_space", "2", "Address Space Layout Randomization (ASLR) (should be 2 for strong randomization)"},
        {"net.ipv4.tcp_syncookies", "1", "TCP SYN Cookies (protect against SYN flood attacks)"},
        {"net.ipv4.conf.all.rp_filter", "1", "Source validation (anti-spoofing for all interfaces)"},
        {"net.ipv4.conf.default.rp_filter", "1", "Source validation (anti-spoofing for default interface)"}
    };

    for (const auto& check : sysctlChecks) {
        QPair<QString, QString> result = executeCommand(QString("sysctl -n %1").arg(check.param));
        QString value = result.first;
        QString errorOutput = result.second;

        if (value.isEmpty() && !errorOutput.isEmpty()) {
            emit logMessage(QString("[INFO] Could not retrieve sysctl parameter: %1 (Error: %2)").arg(check.param).arg(errorOutput), "info");
        } else if (value.isEmpty()) {
            emit logMessage(QString("[INFO] Could not retrieve sysctl parameter: %1 (No value found, might not exist)").arg(check.param), "info");
        }
        else if (value == check.expected) {
            emit logMessage(QString("[GOOD] %1: %2 (Expected: %3)").arg(check.description).arg(value).arg(check.expected), "good");
        } else {
            emit logMessage(QString("[RISKY] %1: %2 (Expected: %3). Consider changing to expected value.").arg(check.description).arg(value).arg(check.expected), "risky");
            allGood = false; issues << QString("Sysctl: %1 expected %2, got %3").arg(check.param).arg(check.expected).arg(value);
            emit logMessage(QString("  Recommendation: To set this permanently, create/edit a file in /etc/sysctl.d/ (e.g., /etc/sysctl.d/99-security.conf) and add the line '%1 = %2'. Then apply with 'sudo sysctl -p'.").arg(check.param).arg(check.expected), "info");
        }
    }
}

void SecurityScanner::_checkOutdatedPackages(bool &allGood, QStringList &issues) {
    emit logMessage("Initiating Outdated Packages Audit (requires 'apt' and internet access).", "info");

    emit logMessage("Running 'pkexec apt update' to refresh package lists...", "info");
    QPair<QString, QString> aptUpdateResult = executePrivilegedCommand("apt update");
    QString aptUpdateOutput = aptUpdateResult.first;
    QString aptUpdateError = aptUpdateResult.second;

    if (aptUpdateOutput.contains("E:", Qt::CaseInsensitive) || aptUpdateOutput.contains("failed to fetch", Qt::CaseInsensitive) || !aptUpdateError.isEmpty()) {
        emit logMessage("[DANGER] 'pkexec apt update' failed. Check internet connection, repository configuration, or pkexec permissions.", "danger");
        if (!aptUpdateOutput.isEmpty()) emit logMessage("Error output from apt update (stdout):\n" + aptUpdateOutput, "danger");
        if (!aptUpdateError.isEmpty()) emit logMessage("Error output from apt update (stderr):\n" + aptUpdateError, "danger");
        issues << "Outdated packages check failed (apt update error)";
        allGood = false;
        emit logMessage("  Recommendation: Ensure your internet connection is active. Verify entries in /etc/apt/sources.list and /etc/apt/sources.list.d/ are correct. Run 'sudo apt update' in a terminal to check for specific error messages.", "info");
        return;
    } else {
        emit logMessage("'pkexec apt update' successful. Checking for upgradable packages...", "info");
    }

    QPair<QString, QString> aptListResult = executeCommand("apt list --upgradable");
    QString aptListUpgradable = aptListResult.first;
    QString aptListError = aptListResult.second;

    if (!aptListError.isEmpty() && aptListUpgradable.isEmpty()) {
        emit logMessage(QString("[WARNING] 'apt list --upgradable' failed. Error: %1").arg(aptListError), "risky");
        issues << "Outdated packages check failed (apt list error)";
        allGood = false;
        return;
    }

    QStringList upgradablePackages = aptListUpgradable.split('\n', Qt::SkipEmptyParts);

    if (upgradablePackages.size() > 1) {
        emit logMessage("[RISKY] Outdated packages found. Update your system regularly for security patches:", "risky");
        allGood = false;
        for (int i = 1; i < upgradablePackages.size(); ++i) {
            QString pkgLine = upgradablePackages.at(i).trimmed();
            emit logMessage(" - " + pkgLine, "risky");
            issues << "Outdated package: " + pkgLine.section('/', 0, 0);
        }
        emit logMessage("  Recommendation: Run 'sudo apt update && sudo apt upgrade' in your terminal to apply all pending security and feature updates. Reboot if a kernel or critical system component was updated.", "info");
    } else {
        emit logMessage("[GOOD] No outdated packages found. Your system is up to date.", "good");
    }
}