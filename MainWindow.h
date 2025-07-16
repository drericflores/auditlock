#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTextEdit>
#include <QProgressBar>
#include <QAction>
#include <QCheckBox>   // For filter checkboxes
#include <QList>       // For storing log entries
#include <QScrollBar>  // For direct QScrollBar access in applyLogFilters()
#include "SecurityScanner.h" // Essential for SecurityScanner class definition

// Define a struct to hold log entry data for the interactive log view
struct LogEntry {
    QString message;     // Raw message text
    QString level;       // Level of the message (e.g., "good", "info", "risky", "danger", "section_header")
    QString htmlMessage; // Pre-formatted HTML message with color and formatting
    bool isHeader = false; // Flag to indicate if this entry is a section header
};

class MainWindow : public QMainWindow {
    Q_OBJECT // This macro is crucial for Qt's meta-object system (signals/slots)
public:
    explicit MainWindow(QWidget *parent = nullptr); // Use explicit for single-argument constructors

private slots:
    // Existing slots for main UI functionality
    void startFullScan();
    void appendLog(const QString &msg, const QString &level);
    void scanFinished(bool secure, const QStringList &issues);
    void saveReport();
    void copySelection();
    void copyReport();
    void showAbout();

    // Slots for individual security checks
    void checkPasswordPolicyTriggered();
    void checkKernelParamsTriggered();
    void checkOutdatedPackagesTriggered();

    // Slots for progress updates
    void updateProgressBar(int value);
    void setProgressBarMax(int max);

    // Slot for log filtering
    void filterLogs();

private:
    void setupMenus(); // Helper function to set up the menu bar
    void resetScannerAndStart(); // Helper to manage scanner lifecycle for new scans
    void applyLogFilters(); // Helper to apply filters and refresh the log view

    // UI elements
    QTextEdit *output;
    QProgressBar *progress;

    // Scanner instance (worker thread)
    SecurityScanner *scanner = nullptr;

    // Actions for menu items
    QAction *saveAction;
    QAction *passwordPolicyAction;
    QAction *kernelParamsAction;
    QAction *outdatedPackagesAction;

    // UI elements for log filtering
    QCheckBox *showGoodCb;
    QCheckBox *showInfoCb;
    QCheckBox *showRiskyCb;
    QCheckBox *showDangerCb;
    QCheckBox *showAllCb;

    // Internal storage for all log entries
    QList<LogEntry> allLogEntries;
};

#endif // MAINWINDOW_H