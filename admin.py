import os
import sys
import ctypes
from PySide6.QtWidgets import QMessageBox, QMainWindow, QLabel, QVBoxLayout, QWidget

def check_privileges():
    """Check for administrative/root privileges based on the operating system."""
    if os.name == 'nt':  
        if not ctypes.windll.shell32.IsUserAnAdmin():
            
            QMessageBox.critical(
                None,
                "Permission Error",
                "This application requires administrative privileges. Please run as administrator."
            )
           
            params = ' '.join([f'"{arg}"' for arg in sys.argv])
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
            sys.exit(0)
    else:
        if os.geteuid() != 0: 
            QMessageBox.critical(
                None,
                "Permission Error",
                "This application requires root privileges. Please run as root."
            )
            sys.exit(1)

class MainWindow(QMainWindow):
    """Main application window shown if admin/root privileges are available."""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Admin-Required Application")

        central_widget = QWidget()
        layout = QVBoxLayout()
        label = QLabel("Application running with admin/root privileges!")
        layout.addWidget(label)
        central_widget.setLayout(layout)
        
        self.setCentralWidget(central_widget)
  
if __name__ == "__main__":
    check_privileges()  # Check for privileges and relaunch if necessary

    # Proceed with the rest of your application logic
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
