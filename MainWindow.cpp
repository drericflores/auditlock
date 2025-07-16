#include "MainWindow.h"
#include <QApplication>   // Needed for QApplication (e.g., clipboard access)
#include <QMenuBar>       // For QMenuBar
#include <QMenu>          // For QMenu
#include <QVBoxLayout>    // For vertical layout
#include <QHBoxLayout>    // For horizontal layout (e.g., filter checkboxes)
#include <QFileDialog>    // For QFileDialog (saving reports)
#include <QTextStream>    // For QTextStream (writing to file)
#include <QTabWidget>     // For QTabWidget (in About dialog)
#include <QLabel>         // For QLabel (in About dialog and filter labels)
#include <QClipboard>     // For QClipboard (copying text)
#include <QMessageBox>    // For QMessageBox (warning/error dialogs)
#include <QDialog>        // For QDialog (About dialog)
#include <QScrollBar>     // Essential for direct QScrollBar access in applyLogFilters()


// Constructor for MainWindow
MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    // Initialize primary UI elements
    output = new QTextEdit;
    output->setReadOnly(true); // Make the text edit read-only for displaying logs

    progress = new QProgressBar;
    progress->setRange(0, 100); // Default range for progress bar, will be updated by scanner
    progress->setValue(0);     // Initial value

    // --- New UI elements for Log Filtering ---
    showGoodCb = new QCheckBox("Good");
    showInfoCb = new QCheckBox("Info");
    showRiskyCb = new QCheckBox("Risky");
    showDangerCb = new QCheckBox("Danger");
    showAllCb = new QCheckBox("All"); // Checkbox to show all messages

    // Connect checkboxes to the filter slot, so logs update when selections change
    connect(showGoodCb, &QCheckBox::stateChanged, this, &MainWindow::filterLogs);
    connect(showInfoCb, &QCheckBox::stateChanged, this, &MainWindow::filterLogs);
    connect(showRiskyCb, &QCheckBox::stateChanged, this, &MainWindow::filterLogs);
    connect(showDangerCb, &QCheckBox::stateChanged, this, &MainWindow::filterLogs);
    connect(showAllCb, &QCheckBox::stateChanged, this, &MainWindow::filterLogs);

    // Set initial filter states (show all by default, but "All" checkbox is unchecked initially)
    showGoodCb->setChecked(true);
    showInfoCb->setChecked(true);
    showRiskyCb->setChecked(true);
    showDangerCb->setChecked(true);
    showAllCb->setChecked(false); // "All" is managed by filterLogs logic

    // Layout for filter checkboxes
    QHBoxLayout *filterLayout = new QHBoxLayout;
    filterLayout->addWidget(new QLabel("Show:"));
    filterLayout->addWidget(showGoodCb);
    filterLayout->addWidget(showInfoCb);
    filterLayout->addWidget(showRiskyCb);
    filterLayout->addWidget(showDangerCb);
    filterLayout->addStretch(); // Pushes checkboxes to the left
    filterLayout->addWidget(showAllCb);
    // ---------------------------------------

    // Set up the central widget and main layout
    QWidget *central = new QWidget;
    auto *mainLayout = new QVBoxLayout(central);
    mainLayout->addLayout(filterLayout); // Add filters above the output area
    mainLayout->addWidget(output);      // Add the text output area
    mainLayout->addWidget(progress);    // Add the progress bar
    setCentralWidget(central);          // Set this widget as the main window's central widget

    // Setup menus and initial window properties
    setupMenus();
    setWindowTitle("LockAudit");
    resize(800, 600); // Set initial window size
}

// Function to set up all menu items
void MainWindow::setupMenus() {
    // --- File Menu ---
    auto *fileMenu = menuBar()->addMenu("File");
    saveAction = fileMenu->addAction("Save Report");
    saveAction->setEnabled(false); // Disable until a scan is complete
    connect(saveAction, &QAction::triggered, this, &MainWindow::saveReport);
    fileMenu->addAction("Quit", this, &QWidget::close); // Standard quit action

    // --- Edit Menu ---
    auto *editMenu = menuBar()->addMenu("Edit");
    // Corrected QMenu::addAction syntax for connecting directly to a slot
    editMenu->addAction("Copy", this, &MainWindow::copySelection);
    editMenu->addAction("Copy Report", this, &MainWindow::copyReport);

    // --- Run Full Audit Menu ---
    auto *runMenu = menuBar()->addMenu("Run Full Audit");
    // Corrected QMenu::addAction syntax
    runMenu->addAction("Start Full Audit", this, &MainWindow::startFullScan);

    // --- Security Checks Menu (New Enhancement) ---
    // This is the menu that allows individual audit checks
    auto *securityChecksMenu = menuBar()->addMenu("Security Checks");

    passwordPolicyAction = securityChecksMenu->addAction("Check Password Policy");
    connect(passwordPolicyAction, &QAction::triggered, this, &MainWindow::checkPasswordPolicyTriggered);

    kernelParamsAction = securityChecksMenu->addAction("Check Kernel Parameters (Sysctl)");
    connect(kernelParamsAction, &QAction::triggered, this, &MainWindow::checkKernelParamsTriggered);

    outdatedPackagesAction = securityChecksMenu->addAction("Check Outdated Packages");
    connect(outdatedPackagesAction, &QAction::triggered, this, &MainWindow::checkOutdatedPackagesTriggered);

    // --- Help Menu ---
    auto *helpMenu = menuBar()->addMenu("Help");
    // Corrected QMenu::addAction syntax
    helpMenu->addAction("About", this, &MainWindow::showAbout);
}

// Helper function to manage the SecurityScanner lifecycle before starting a new scan
void MainWindow::resetScannerAndStart() {
    if (scanner) {
        // If a scan is currently running, gracefully stop the thread
        scanner->quit();
        scanner->wait(); // Wait for the thread's run() method to finish execution
        delete scanner; // Delete the old scanner object
        scanner = nullptr; // Reset pointer
    }
    output->clear(); // Clear previous log output in the QTextEdit
    allLogEntries.clear(); // CRITICAL: Clear stored log entries for a fresh scan

    progress->setRange(0, 0); // Set progress bar to indeterminate state
    progress->setValue(0);
    saveAction->setEnabled(false); // Disable save until new scan is complete

    // Create a new SecurityScanner instance
    scanner = new SecurityScanner(this); // 'this' sets MainWindow as parent for proper object cleanup

    // Connect signals and slots for communication between scanner and UI
    connect(scanner, &SecurityScanner::logMessage, this, &MainWindow::appendLog);
    connect(scanner, &SecurityScanner::scanComplete, this, &MainWindow::scanFinished);
    // Connect new signals for progress updates
    connect(scanner, &SecurityScanner::scanProgress, this, &MainWindow::updateProgressBar);
    connect(scanner, &SecurityScanner::setMaxProgress, this, &MainWindow::setProgressBarMax);

    // Reset filter checkboxes to their default "show all basic" state for a new scan
    showGoodCb->setChecked(true);
    showInfoCb->setChecked(true);
    showRiskyCb->setChecked(true);
    showDangerCb->setChecked(true);
    showAllCb->setChecked(false); // "All" is managed by filterLogs logic, usually off by default
}

// Slot for "Start Full Audit" menu action
void MainWindow::startFullScan() {
    resetScannerAndStart(); // Prepare the UI and scanner
    output->append("Starting a full system audit...");
    scanner->startFullAudit(); // Command the scanner to run a full audit
}

// Slot for "Check Password Policy" menu action
void MainWindow::checkPasswordPolicyTriggered() {
    resetScannerAndStart();
    output->append("Checking password policy...");
    scanner->checkPasswordPolicy(); // Command the scanner to run this specific check
}

// Slot for "Check Kernel Parameters (Sysctl)" menu action
void MainWindow::checkKernelParamsTriggered() {
    resetScannerAndStart();
    output->append("Checking kernel parameters (sysctl)...");
    scanner->checkKernelParams(); // Command the scanner to run this specific check
}

// Slot for "Check Outdated Packages" menu action
void MainWindow::checkOutdatedPackagesTriggered() {
    resetScannerAndStart();
    output->append("Checking for outdated packages (requires 'apt' and internet access)...");
    scanner->checkOutdatedPackages(); // Command the scanner to run this specific check
}

// Slot to append messages to the log output area (now stores and calls filter)
void MainWindow::appendLog(const QString &msg, const QString &level) {
    QString color;
    QString htmlMsg;
    bool isHeader = false; // Default to false

    // Determine text color and specific formatting based on message level
    if (level == "good") {
        color = "green";
        htmlMsg = QString("<span style='color:%1;'>%2</span>").arg(color, msg.toHtmlEscaped());
    } else if (level == "risky") {
        color = "orange";
        htmlMsg = QString("<span style='color:%1;'>%2</span>").arg(color, msg.toHtmlEscaped());
    } else if (level == "danger") {
        color = "red";
        htmlMsg = QString("<span style='color:%1;'>%2</span>").arg(color, msg.toHtmlEscaped());
    } else if (level == "section_header") { // Handle new section header level
        color = "blue"; // Distinct color for headers
        // Add bolding and line breaks for visual separation
        htmlMsg = QString("<br><span style='color:%1; font-weight:bold;'>%2</span><br>").arg(color, msg.toHtmlEscaped());
        isHeader = true; // Mark as header
    }
    else { // Default for "info" or any other levels
        color = "black";
        htmlMsg = QString("<span style='color:%1;'>%2</span>").arg(color, msg.toHtmlEscaped());
    }

    // Create a LogEntry and store it internally
    LogEntry entry;
    entry.message = msg;
    entry.level = level;
    entry.htmlMessage = htmlMsg;
    entry.isHeader = isHeader; // Set the isHeader flag
    allLogEntries.append(entry); // Add to the list of all log entries

    // Reapply filters to update the visible log in the QTextEdit
    applyLogFilters();
}

// Slot executed when a scan completes
void MainWindow::scanFinished(bool secure, const QStringList &issues) {
    // Ensure progress bar is at 100% when scan is truly finished
    progress->setRange(0, 100); // Set to full range just in case
    progress->setValue(100);    // Set to 100%

    // Append final verdict based on scan results
    if (secure && issues.isEmpty()) {
        appendLog("\nLockAudit verdict: SYSTEM SECURE. No issues found for this check.", "good");
    } else {
        appendLog("\nLockAudit verdict: SYSTEM NEEDS WORK. Issues found:", "danger");
        // Append individual issues from the summary list
        for (const QString &issue : issues) {
            appendLog(" - " + issue, "danger");
        }
    }
    saveAction->setEnabled(true); // Enable save report functionality
    filterLogs(); // Final filter apply to ensure everything is correctly displayed post-scan
}

// Slot to update the progress bar's current value
void MainWindow::updateProgressBar(int value) {
    progress->setValue(value);
}

// Slot to set the progress bar's maximum range
void MainWindow::setProgressBarMax(int max) {
    progress->setRange(0, max);
    progress->setValue(0); // Reset progress to 0 when a new max is set
}

// Slot for handling log filter checkbox changes
void MainWindow::filterLogs() {
    bool allCheckedState = showAllCb->isChecked();
    if (allCheckedState) {
        // If "All" is checked, uncheck all other individual filter checkboxes programmatically.
        // Block signals to prevent recursive calls to filterLogs() during this programmatic change.
        showGoodCb->blockSignals(true); showGoodCb->setChecked(false); showGoodCb->blockSignals(false);
        showInfoCb->blockSignals(true); showInfoCb->setChecked(false); showInfoCb->blockSignals(false);
        showRiskyCb->blockSignals(true); showRiskyCb->setChecked(false); showRiskyCb->blockSignals(false);
        showDangerCb->blockSignals(true); showDangerCb->setChecked(false); showDangerCb->blockSignals(false);
    } else if (!showGoodCb->isChecked() && !showInfoCb->isChecked() &&
               !showRiskyCb->isChecked() && !showDangerCb->isChecked()) {
        // If "All" is not checked, AND all other individual filter checkboxes are also unchecked,
        // we programmatically check "All" to ensure something is always displayed, unless there are no logs.
        if (!allLogEntries.isEmpty()) {
            showAllCb->blockSignals(true); // Block signals to avoid re-triggering filterLogs
            showAllCb->setChecked(true);
            showAllCb->blockSignals(false);
            // applyLogFilters() will be called next based on this change.
        }
    }
    // Now apply the filters based on the (potentially adjusted) checkbox states
    applyLogFilters();
}

// Helper function to clear the log view and re-populate it based on active filters
void MainWindow::applyLogFilters() {
    output->clear(); // Clear current text in QTextEdit view

    bool showGood = showGoodCb->isChecked();
    bool showInfo = showInfoCb->isChecked();
    bool showRisky = showRiskyCb->isChecked();
    bool showDanger = showDangerCb->isChecked();
    bool showAll = showAllCb->isChecked(); // Get current state of "All" checkbox

    for (const LogEntry &entry : allLogEntries) {
        bool display = false;
        if (entry.isHeader) { // Always display headers regardless of filter settings
            display = true;
        } else if (showAll) { // If "All" is checked, display everything (non-headers too)
            display = true;
        } else { // Otherwise, apply individual filters based on level
            if (showGood && entry.level == "good") display = true;
            else if (showInfo && entry.level == "info") display = true;
            else if (showRisky && entry.level == "risky") display = true;
            else if (showDanger && entry.level == "danger") display = true;
        }

        if (display) {
            output->append(entry.htmlMessage); // Append the pre-formatted HTML message
        }
    }
    // Scroll to the bottom after applying filters to show latest messages
    output->verticalScrollBar()->setValue(output->verticalScrollBar()->maximum());
}

// Slot to save the report to a file
void MainWindow::saveReport() {
    QString filename = QFileDialog::getSaveFileName(this, "Save LockAudit Report", "LockAudit.txt", "Text Files (*.txt)");
    if (!filename.isEmpty()) {
        QFile f(filename);
        if (f.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&f);
            // When saving, write the raw message text from all stored logs, regardless of current filter
            for (const LogEntry &entry : allLogEntries) {
                // Ensure headers are written properly without HTML tags for plain text file
                if (entry.isHeader) {
                    out << "\n--- " << entry.message.trimmed().remove("---").trimmed() << " ---\n\n"; // Reformat header for plain text
                } else {
                    out << entry.message << "\n"; // Write raw message text
                }
            }
            f.close();
        } else {
            QMessageBox::warning(this, "Save Error", "Could not save report to " + filename + "\n" + f.errorString());
        }
    }
}

// Slot to copy selected text from the output log to clipboard
void MainWindow::copySelection() {
    output->copy();
}

// Slot to copy the entire report (plain text) to the clipboard
void MainWindow::copyReport() {
    QString plainTextReport;
    for (const LogEntry &entry : allLogEntries) {
        if (entry.isHeader) {
            plainTextReport += "\n--- " + entry.message.trimmed().remove("---").trimmed() + " ---\n\n";
        } else {
            plainTextReport += entry.message + "\n";
        }
    }
    QApplication::clipboard()->setText(plainTextReport);
}

// Slot to show the "About" dialog
void MainWindow::showAbout() {
    QTabWidget *tabs = new QTabWidget; // Create a tab widget for the dialog
    
    // First tab: About information
    QWidget *tab1 = new QWidget;
    QVBoxLayout *layout1 = new QVBoxLayout;
    layout1->addWidget(new QLabel("Programmed By: Dr. Eric Oliver Flores"));
    layout1->addWidget(new QLabel("Version: 1"));
    layout1->addWidget(new QLabel("Date: June 2025")); // Current time is Tuesday, July 15, 2025 at 12:02:53 PM MDT.
    tab1->setLayout(layout1);

    // Second tab: Technologies used
    QWidget *tab2 = new QWidget;
    QVBoxLayout *layout2 = new QVBoxLayout;
    layout2->addWidget(new QLabel("Technologies:"));
    layout2->addWidget(new QLabel("- C++17"));
    layout2->addWidget(new QLabel("- Qt5 Widgets"));
    layout2->addWidget(new QLabel("- POSIX syscalls"));
    layout2->addWidget(new QLabel("- CMake"));
    tab2->setLayout(layout2);

    // Add tabs to the tab widget
    tabs->addTab(tab1, "About");
    tabs->addTab(tab2, "Technologies");

    // Create the dialog and set its layout
    QDialog *aboutDialog = new QDialog(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(aboutDialog);
    mainLayout->addWidget(tabs);
    aboutDialog->setWindowTitle("About LockAudit");
    aboutDialog->resize(400, 200); // Set dialog size
    aboutDialog->exec(); // Show the dialog modally
}