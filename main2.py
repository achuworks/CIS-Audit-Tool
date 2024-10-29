import os
import sys
import ctypes
from PySide6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QPushButton, QWidget, QLabel, QStackedWidget, QMessageBox
from PySide6.QtCore import Slot
from dashboard import Dashboard
from PySide6.QtCore import QTimer 

def is_admin():
    """Return True if the user has administrative/root privileges, False otherwise."""
    if os.name == 'nt':  # Windows
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except AttributeError:
            return False  # Default to non-admin if API is not available
    else:  # Assuming Linux or other POSIX systems
        return os.geteuid() == 0

def ensure_admin_privileges():
    # Check if on Windows and if the user has admin rights
    if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
        # Initialize QApplication to use QMessageBox
        app = QApplication(sys.argv)
        # Create and show a message box that requests admin access
        msg_box = QMessageBox()
        msg_box.setWindowTitle("Admin Access Required")
        msg_box.setText("This application needs to be run as an administrator. Click OK to restart as admin.")
        msg_box.setIcon(QMessageBox.Critical)
        msg_box.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)

        if msg_box.exec() == QMessageBox.Ok:
            # Relaunch the script with admin rights if user clicks OK
            params = ' '.join([f'"{arg}"' for arg in sys.argv])  # Passes command-line args
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
            sys.exit(0)  # Exit the original script
        else:
            # If the user cancels, exit the program
            sys.exit("User opted not to run with admin privileges.")

class MainWindow(QMainWindow):
    """Main application window that displays access level information."""
    def __init__(self, admin_access):
        super().__init__()
        self.setWindowTitle("Dashboard")

        # Main layout setup
        main_layout = QHBoxLayout()
        sidebar = QWidget()
        sidebar_layout = QVBoxLayout()
        sidebar.setLayout(sidebar_layout)

        # Stacked widget for page navigation
        self.stack = QStackedWidget()
        dashboard = Dashboard()  # Dashboard page
        page2 = QWidget()  # Settings page
        page2.setLayout(QVBoxLayout())
        page2.layout().addWidget(QLabel("This is a page 2 test"))

        self.stack.addWidget(dashboard)
        self.stack.addWidget(page2)

        # Sidebar buttons
        button1 = QPushButton("Dashboard")
        button2 = QPushButton("Settings")
        button1.clicked.connect(lambda: self.change_page(0))
        button2.clicked.connect(lambda: self.change_page(1))

        # Sidebar layout and styles
        sidebar_layout.addWidget(button1)
        sidebar_layout.addWidget(button2)
        sidebar_layout.addStretch(1)
        button1.setCheckable(True)
        button2.setCheckable(True)
        button1.setAutoExclusive(True)
        button2.setAutoExclusive(True)
        sidebar.setMinimumWidth(185)
        sidebar.setMaximumWidth(300)
        sidebar.setStyleSheet(u"QWidget{background-color:#3399ff;color:white;margin:0;padding:0}\n"
                              "QPushButton{border-radius:20px;padding:20px;font-size:16px}"
                              "QPushButton:checked{background-color:#FFFFFF;color:#1F95EF}")

        # Add sidebar and stacked widget to main layout
        main_layout.addWidget(sidebar)
        main_layout.addWidget(self.stack)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Display access level at the top
        access_label = QLabel(f"Access Level: {'Administrator' if admin_access else 'Standard User'}")
        access_label.setStyleSheet("font-size: 18px; font-weight: bold; color: green;" if admin_access else "font-size: 18px; font-weight: bold; color: red;")

        # Main vertical layout to include access label and dashboard
        main_vertical_layout = QVBoxLayout()
        main_vertical_layout.addWidget(access_label)
        main_vertical_layout.addLayout(main_layout)

        # Set central widget
        central_widget = QWidget()
        central_widget.setLayout(main_vertical_layout)
        self.setCentralWidget(central_widget)

        # Create a QTimer to hide the access_label after a few seconds
        QTimer.singleShot(3000, access_label.hide)  # Hide the access label after 3000 milliseconds (3 seconds)


    @Slot(int)
    def change_page(self, index):
        self.stack.setCurrentIndex(index)

# Main application execution
if __name__ == "__main__":
    # Ensure the application is running with admin/root privileges
    ensure_admin_privileges()

    # Determine if running with admin/root privileges
    admin_access = is_admin()

    # Start the main application window
    app = QApplication(sys.argv)
    window = MainWindow(admin_access)
    window.resize(1098, 755)
    window.show()
    sys.exit(app.exec())
