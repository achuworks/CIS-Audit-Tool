import sys
import platform
import subprocess
from PySide6.QtWidgets import QApplication, QWidget, QLabel, QVBoxLayout, QMessageBox, QComboBox, QPushButton

class OSVersionWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("OS Version Checker")
        self.setGeometry(100, 100, 400, 100)

        self.version_label = QLabel("Fetching OS version...", self)
        self.dropdown = QComboBox(self)
        self.confirm_button = QPushButton("Confirm Selection", self)

        layout = QVBoxLayout()
        layout.addWidget(self.version_label)
        layout.addWidget(self.dropdown)
        layout.addWidget(self.confirm_button)
        
        self.dropdown.hide()
        self.confirm_button.hide()

        self.setLayout(layout)
        self.confirm_button.clicked.connect(self.confirm_selection)
        self.check_os_version()

    def check_os_version(self):
        version = platform.system()
        if version == "Linux":
            p1 = subprocess.Popen(["cat", "/etc/os-release"], stdout=subprocess.PIPE)
            p2 = subprocess.Popen(["head", "-n", "1"], stdin=p1.stdout, stdout=subprocess.PIPE)
            linux_version = subprocess.run(["cut", "-d", "=", "-f", "2"], stdin=p2.stdout, capture_output=True, text=True)
            os_version = linux_version.stdout.replace("\"", "").strip()
        else:
            p1 = subprocess.run(["wmic", "os", "get", "name", "/value"], capture_output=True, text=True)
            details = p1.stdout
            os_version = details.split("=")[1].split("|")[0].strip()
            p2 = subprocess.Popen(["systeminfo"],stdout=subprocess.PIPE)
            p3 = subprocess.run(["findstr","/B","Domain"],stdin=p2.stdout,capture_output=True,text=True)
            domain = p3.stdout.split(":")[1].strip()
            if(domain=="WORKGROUP"):
                os_version = os_version + " Standalone"
            else:
                os_version = os_version + " Domain-Joined"
        self.version_label.setText(f"Your Current OS Version: \t{os_version} \n\n\n\n\nChoose OS")
        self.osList(os_version)

    def osList(self, os_version):
        # Add items to the dropdown
        self.dropdown.addItems([
            "Microsoft Windows 11 Enterprise Standalone", 
            "Microsoft Windows 11 Enterprise Domain-Joined", 
            "Microsoft Windows 11 Pro Standalone", 
            "Ubuntu"
        ])
        self.dropdown.show()
        self.confirm_button.show()
        if os_version == "Microsoft Windows 11 Pro Standalone":
            self.dropdown.setCurrentText("Microsoft Windows 11 Pro Standalone")
            
        elif os_version == "Microsoft Windows 11 Enterprise Domain-Joined":
            self.dropdown.setCurrentText("Microsoft Windows 11 Enterprise Domain-Joined")
            
        elif os_version == "Microsoft Windows 11 Enterprise Domain-Joined":
            self.dropdown.setCurrentText("Microsoft Windows 11 Enterprise Domain-Joined")
            
        elif os_version == "Ubuntu":
            self.dropdown.setCurrentText("Ubuntu")

            
    def confirm_selection(self):
        selected_os = self.dropdown.currentText()

        confirm_dialog = QMessageBox.question(self, "Confirm Selection", 
                                          f"Do you want to proceed with {selected_os}?", 
                                          QMessageBox.Yes | QMessageBox.No, 
                                          QMessageBox.No)
    
        if confirm_dialog == QMessageBox.Yes:
            
            self.run_script()
           

    def run_script(self):
        selected_os = self.dropdown.currentText()
        self.close()
        subprocess.run(["python", "components/customScript.py",selected_os])


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = OSVersionWindow()
    window.show()
    sys.exit(app.exec())
