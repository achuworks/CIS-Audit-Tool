import os
import sys
import ctypes
import subprocess
from PySide6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QPushButton, QWidget, QLabel, QStackedWidget, QTextEdit, QMessageBox
from PySide6.QtCore import Slot, QTimer, QUrl
from PySide6.QtWebEngineWidgets import QWebEngineView
from dashboard import Dashboard


def is_admin():
    """Return True if the user has administrative/root privileges, False otherwise."""
    if os.name == 'nt':  
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except AttributeError:
            return False  
    else:
        return os.geteuid() == 0


def ensure_admin_privileges():
    if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
        app = QApplication(sys.argv)

        msg_box = QMessageBox()
        msg_box.setWindowTitle("Admin Access Required")
        msg_box.setText("This application needs to be run as an administrator. Click OK to restart as admin.")
        msg_box.setIcon(QMessageBox.Critical)
        msg_box.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)

        if msg_box.exec() == QMessageBox.Ok:
            params = ' '.join([f'"{arg}"' for arg in sys.argv])  
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
            sys.exit(0)  
        else:
            sys.exit("User opted not to run with admin privileges.")


class MainWindow(QMainWindow):
    """Main application window that displays access level information."""
    def __init__(self, admin_access):
        super().__init__()
        self.setWindowTitle("Dashboard")

        main_layout = QHBoxLayout()
        sidebar = QWidget()
        sidebar_layout = QVBoxLayout()
        sidebar.setLayout(sidebar_layout)

        self.stack = QStackedWidget()
        dashboard = Dashboard()
        settings_page = QWidget()
        settings_page.setLayout(QVBoxLayout())
        settings_page.layout().addWidget(QLabel("This is a page 2 test"))

        self.report_page = QWidget()
        self.report_page.setLayout(QVBoxLayout())
        self.report_output = QTextEdit()
        self.report_output.setReadOnly(True)
        self.report_page.layout().addWidget(QLabel("Report Output:"))
        self.report_page.layout().addWidget(self.report_output)

        self.stack.addWidget(dashboard)
        self.stack.addWidget(settings_page)
        self.stack.addWidget(self.report_page)

        button1 = QPushButton("Dashboard")
        button3 = QPushButton("Generate Report")
        button4 = QPushButton("Remediation")

        button1.clicked.connect(lambda: self.change_page(0))
  
        button3.clicked.connect(self.show_remediation)
        button4.clicked.connect(self.show_remediation)  

        sidebar_layout.addWidget(button1)
        sidebar_layout.addWidget(button3)
        sidebar_layout.addWidget(button4)
        sidebar_layout.addStretch(1)

        button1.setCheckable(True)
 
        button3.setCheckable(True)
        button4.setCheckable(True)
        button1.setAutoExclusive(True)
     
        button3.setAutoExclusive(True)
        button4.setAutoExclusive(True)

        sidebar.setMinimumWidth(185)
        sidebar.setMaximumWidth(300)
        sidebar.setStyleSheet(u"QWidget{background-color:#3399ff;color:white;margin:0;padding:0}\n"
                              "QPushButton{border-radius:20px;padding:20px;font-size:16px} "
                              "QPushButton:checked{background-color:#FFFFFF;color:#1F95EF}")

        main_layout.addWidget(sidebar)
        main_layout.addWidget(self.stack)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        access_label = QLabel(f"Access Level: {'Administrator' if admin_access else 'Standard User'}")
        access_label.setStyleSheet("font-size: 18px; font-weight: bold; color: green;" if admin_access else "font-size: 18px; font-weight: bold; color: red;")

        main_vertical_layout = QVBoxLayout()
        main_vertical_layout.addWidget(access_label)
        main_vertical_layout.addLayout(main_layout)

        central_widget = QWidget()
        central_widget.setLayout(main_vertical_layout)
        self.setCentralWidget(central_widget)

        QTimer.singleShot(3000, access_label.hide)

    @Slot(int)
    def change_page(self, index):
        self.stack.setCurrentIndex(index)

    @Slot()
    def generate_report(self):
        """Executes the report generation script and displays the output."""
        try:
            result = subprocess.run(
                [sys.executable, 'rep.py'], 
                capture_output=True,
                text=True,
                check=True
            )
            output = result.stdout.strip()
            self.report_output.setPlainText(output or "No output generated.")
            self.change_page(2)
        except subprocess.CalledProcessError as e:
            self.report_output.setPlainText(f"Error running report: {e.stderr.strip()}")
            self.change_page(2)

    @Slot()
    def show_remediation(self):
        """Open the HTML report and filter to show only remediation (red) issues."""
        self.html_viewer = HTMLViewer(QUrl.fromLocalFile(os.path.abspath('merged_report.html')))
        self.html_viewer.filter_red_issues()  # Load and show only red (remediation) parts
        self.html_viewer.show()


class HTMLViewer(QMainWindow):
    def __init__(self, html_path):
        super().__init__()
        self.browser = QWebEngineView()
        self.browser.setUrl(html_path)
        self.setCentralWidget(self.browser)
        self.setWindowTitle("Report")

    def filter_red_issues(self):
        """Apply JavaScript to display only red issues in the HTML report."""
        script = """
        document.querySelectorAll('body *').forEach(el => {
            if (window.getComputedStyle(el).color !== 'rgb(255, 0, 0)') { 
                el.style.display = 'none'; 
            }
        });
        """
        self.browser.page().runJavaScript(script)


if __name__ == "__main__":
    ensure_admin_privileges()
    admin_access = is_admin()
    app = QApplication(sys.argv)
    window = MainWindow(admin_access)
    window.resize(1098, 755)
    window.show()
    sys.exit(app.exec())
