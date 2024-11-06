import sys
from PySide6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout,
                               QCheckBox, QLabel, QLineEdit, QPushButton, QProgressBar, QWidget, QFileDialog, QMessageBox)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont

class InstallationWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Installation")
        self.setFixedSize(800, 600)
        main_layout = QVBoxLayout()

        title_label = QLabel("Welcome to Solid Umbrella")
        title_label.setFont(QFont("Arial", 18, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("color: #ffffff; margin-bottom: 15px;")
        main_layout.addWidget(title_label)

        # License Text
        license_text = (
            "License Agreement:\nYour license terms go here...\n\n"
            "This application helps you to reduce the risk by analyzing the vulnerability in your system and network connection. "
            "You can modify the remediation steps as per the necessity.\n\n"
            "1. Acceptance:\nBy accessing the Application, you confirm your agreement to these Terms. "
            "If you do not agree, do not use the Application.\n\n"
            "2. License and Access:\nYou are granted a limited, non-exclusive license to use the Application for internal purposes. "
            "The Application must be run as an administrator to function properly.\n\n"
            "3. User Responsibilities:\nYou must ensure compliance with these Terms within your organization and maintain the confidentiality of your login credentials.\n\n"
            "4. Disclaimers and Limitation of Liability:\nThe Application is provided 'as is' and 'as available' without warranties of any kind, either express or implied.\n\n"
            "Happy Journey!"
        )
        license_label = QLabel(license_text)
        license_label.setWordWrap(True)
        license_label.setStyleSheet("color: #e0e0e0; background-color: #333333; padding: 10px; border-radius: 5px;")
        main_layout.addWidget(license_label)

        # License Agreement Checkbox
        checkbox = QCheckBox("I accept the License Agreement")
        checkbox.setStyleSheet("color: #ffffff; padding: 5px; font-size: 14px;")
        main_layout.addWidget(checkbox)

        # Installation Path Label and Input
        path_layout = QHBoxLayout()
        path_label = QLabel("Installation Path:")
        path_label.setStyleSheet("color: #ffffff; font-size: 14px;")
        
        # Path input field, initially empty
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("Select installation path")
        self.path_input.setStyleSheet("background-color: #444444; color: #ffffff; padding: 5px; border-radius: 5px;")
        
        # Browse button with functionality to open file dialog
        browse_button = QPushButton("Browse...")
        browse_button.setStyleSheet("background-color: #555555; color: #ffffff; padding: 5px; border-radius: 5px;")
        browse_button.clicked.connect(self.browse_installation_path)  # Connect to browse function
        
        path_layout.addWidget(path_label)
        path_layout.addWidget(self.path_input)
        path_layout.addWidget(browse_button)
        main_layout.addLayout(path_layout)

        # Install Button
        install_button = QPushButton("Install")
        install_button.setEnabled(False)  # Only enable after checkbox is selected
        install_button.setStyleSheet("""
            QPushButton {
                background-color: #1F95EF;
                color: #FFFFFF;
                padding: 10px;
                font-size: 16px;
                border-radius: 5px;
            }
            QPushButton:disabled {
                background-color: #888888;
                color: #CCCCCC;
            }
        """)
        install_button.clicked.connect(self.start_installation)
        
        # Enable install button when checkbox is checked
        checkbox.stateChanged.connect(lambda: install_button.setEnabled(checkbox.isChecked()))
        main_layout.addWidget(install_button)

        # Progress Bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: #333333;
                color: #FFFFFF;
                border-radius: 5px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #1F95EF;
                border-radius: 5px;
            }
        """)
        main_layout.addWidget(self.progress_bar)

        # Central Widget
        central_widget = QWidget()
        central_widget.setLayout(main_layout)
        central_widget.setStyleSheet("background-color: #222222;")
        self.setCentralWidget(central_widget)

        # Timer for installation progress
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_progress)
        self.progress_value = 0  # Initialize progress value

    def browse_installation_path(self):
        # Open file dialog to select installation path
        file_dialog = QFileDialog.getExistingDirectory(self, "Select Installation Directory")
        if file_dialog:
            self.path_input.setText(file_dialog)  # Set the selected path

    def start_installation(self):
        # Check if the installation path is provided
        installation_path = self.path_input.text()
        if not installation_path:
            QMessageBox.warning(self, "Warning", "Please select an installation path.")
            return  # Exit the method if the path is not set

        self.progress_value = 0  # Reset progress value
        self.progress_bar.setValue(self.progress_value)  # Set progress bar to 0
        self.timer.start(100)  # Start timer with 100ms interval (adjust for desired speed)

    def update_progress(self):
        if self.progress_value < 100:
            self.progress_value += 1  # Increment progress value
            self.progress_bar.setValue(self.progress_value)  # Update progress bar
        else:
            self.timer.stop()  # Stop the timer when complete

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = InstallationWindow()
    window.show()
    sys.exit(app.exec())
