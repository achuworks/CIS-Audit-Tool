import sys
import platform
import subprocess
from PySide6.QtWidgets import QApplication, QWidget, QLabel, QVBoxLayout, QMessageBox, QComboBox, QPushButton

class OSVersionWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("OS Version Checker")
        self.setGeometry(100, 100, 400, 200)

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

        self.version_label.setText(f"OS Version: {os_version}")
        self.ask_for_confirmation(os_version)

    def ask_for_confirmation(self, os_version):
        reply = QMessageBox.question(
            self,
            "Confirm OS Version",
            f"Do you want to keep the displayed OS version?\n\n{os_version}",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            self.version_label.setText(f"OS Version confirmed: {os_version}")
            self.dropdown.hide()
            self.confirm_button.hide()
        else:
            self.show_dropdown()

    def show_dropdown(self):
        self.dropdown.addItems(["Windows 11", "Ubuntu"])
        self.dropdown.show()
        self.confirm_button.show()

    def confirm_selection(self):
        selected_os = self.dropdown.currentText()
        self.version_label.setText(f"Selected OS Version: {selected_os}")
        self.dropdown.hide()
        self.confirm_button.hide()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = OSVersionWindow()
    window.show()
    sys.exit(app.exec())
