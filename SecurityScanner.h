#ifndef SECURITYSCANNER_H
#define SECURITYSCANNER_H

#include <QThread>
#include <QDir>
#include <QProcess>
#include <QRegularExpression> // Essential for QRegularExpression and QRegularExpressionMatch
#include <QRegularExpressionMatch> // Essential for QRegularExpression and QRegularExpressionMatch

class SecurityScanner : public QThread {
    Q_OBJECT
public:
    explicit SecurityScanner(QObject *parent = nullptr); // Added explicit keyword for clarity

    // Public methods to start specific audits (public interface)
    void startFullAudit();
    void checkPasswordPolicy();
    void checkKernelParams();
    void checkOutdatedPackages();

signals:
    void logMessage(const QString &message, const QString &level);
    void scanComplete(bool secure, QStringList issues);
    // --- Signals for progress updates ---
    void scanProgress(int value);
    void setMaxProgress(int maximum);
    // ------------------------------------

protected:
    void run() override; // The main run loop for the thread

private:
    // Helper functions for executing commands (now return QPair<QString, QString> for stdout/stderr)
    QPair<QString, QString> executeCommand(const QString &command);
    QPair<QString, QString> executePrivilegedCommand(const QString &command);

    // Private helper functions for the core audit phases
    void _checkSshRootLogin(bool &allGood, QStringList &issues);
    void _scanSuid(const QString &path, const QStringList &safeSuid, bool &allGood, QStringList &issues, int &progress_counter);
    void _scanWorldWritable(const QDir &dir, const QStringList &stickyBitOkPaths, bool &allGood, QStringList &issues, int &progress_counter);
    void _scanPorts(bool &allGood, QStringList &issues);
    void _checkFirewall(bool &allGood, QStringList &issues);

    // Private helper functions for the new individual checks
    void _checkPasswordPolicy(bool &allGood, QStringList &issues);
    void _checkKernelParams(bool &allGood, QStringList &issues);
    void _checkOutdatedPackages(bool &allGood, QStringList &issues);

    // Flags to control which audit is run when `run()` is executed (member variables)
    bool _runFullAudit = false;
    bool _runPasswordPolicyCheck = false;
    bool _runKernelParamsCheck = false;
    bool _runOutdatedPackagesCheck = false;
};

#endif // SECURITYSCANNER_H