from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QMainWindow, QCheckBox, QScrollArea, QPushButton, QGridLayout, QListWidget, QHBoxLayout, QTreeWidget, QTreeWidgetItem
)
from PySide6.QtCore import Qt
import sys
import csv
import os

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Customizable Settings Application")
        self.setGeometry(100, 100, 800, 600)  

        self.setStyleSheet("background-color: white;")

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        self.central_widget.setStyleSheet("background-color: white; color: black;")

        self.main_layout = QGridLayout(self.central_widget)
        self.main_layout.setContentsMargins(30, 20, 30, 20)
        self.main_layout.setSpacing(15)

        self.label = QLabel("Customize your settings", self)
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setStyleSheet("font-size: 18px; font-weight: bold; color: #333;")
        self.main_layout.addWidget(self.label, 0, 0, 1, 2)

        self.available_settings_label = QLabel("Available Settings", self)
        self.available_settings_label.setAlignment(Qt.AlignCenter)
        self.available_settings_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #333;")
        self.main_layout.addWidget(self.available_settings_label, 1, 0)

        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_content = QWidget()
        self.scroll_layout = QVBoxLayout(self.scroll_content)
        self.scroll_content.setStyleSheet("background-color: white;")  
        self.scroll_layout.setContentsMargins(0, 0, 0, 0)
        self.scroll_layout.setSpacing(10)
        self.scroll_area.setWidget(self.scroll_content)
        self.scroll_area.setFixedHeight(400)  

        self.main_layout.addWidget(self.scroll_area, 2, 0)

        self.chosen_settings_label = QLabel("Chosen Settings", self)
        self.chosen_settings_label.setAlignment(Qt.AlignCenter)
        self.chosen_settings_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #333;")
        self.main_layout.addWidget(self.chosen_settings_label, 1, 1)

        self.chosen_settings_list = QListWidget()
        self.chosen_settings_list.setStyleSheet("background-color: #f0f0f0; font-size: 14px; color: #333;")
        self.main_layout.addWidget(self.chosen_settings_list, 2, 1)

        self.apply_button = QPushButton("Next")
        self.apply_button.setCheckable(True)
        self.apply_button.setAutoExclusive(True)
        self.apply_button.setStyleSheet("font-size: 16px; padding: 10px; background-color: #e0e0e0;")
        self.apply_button.clicked.connect(self.run_script)

        self.import_button = QPushButton("Import")
        self.import_button.setCheckable(True)
        self.import_button.setAutoExclusive(True)
        self.import_button.setStyleSheet("font-size: 16px; padding: 10px; background-color: #e0e0e0;")
        #self.import_button.clicked.connect(self.import_settings)
        
        self.export_button = QPushButton("Export")
        self.export_button.setCheckable(True)
        self.export_button.setAutoExclusive(True)
        self.export_button.setStyleSheet("font-size: 16px; padding: 10px; background-color: #e0e0e0;")
        self.export_button.clicked.connect(self.export_settings)

        self.button_layout = QHBoxLayout()
        self.button_layout.addWidget(self.import_button)
        self.button_layout.addWidget(self.export_button)
        self.button_layout.addWidget(self.apply_button)
        
        self.main_layout.addLayout(self.button_layout, 3, 0, 1, 2)

        #self.load_buttons_from_txt("available_scripts.txt")
        #self.load_chosen_settings("custom_scripts.txt")
        data = {"Network Security":["IPv6","Bluetooth","IP Forwarding","Packet redirection","Bogus ICMP response","Broadcast ICMP requests","ICMP Redirects","Secure ICMP Redirects","Reverse Path finding"]}
        self.tree  = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.itemChanged.connect(self.update_chosen_settings)
        self.scroll_layout.addWidget(self.tree)
        for category, items in data.items():
            category_item = QTreeWidgetItem(self.tree)
            category_item.setText(0, category)
            for item in items:
                child = QTreeWidgetItem(category_item)
                child.setFlags(child.flags() | Qt.ItemIsUserCheckable)
                child.setText(0, item)
                child.setCheckState(0, Qt.Unchecked)

    def update_chosen_settings(self):
        self.chosen_settings_list.clear()
        self.collect_checked_items(self.tree.invisibleRootItem())

    def collect_checked_items(self,parent):
        for i in range(parent.childCount()):
            child = parent.child(i)
            if child.checkState(0) == Qt.Checked:
                self.chosen_settings_list.addItem(child.text(0))
            if child.childCount() > 0:
                self.collect_checked_items(child)

    def run_script(self):
        pass

    def export_settings(self):
        self.settings = []
        self.collectsettings(self.tree.invisibleRootItem())
        print(self.settings)
    def collectsettings(self,parent):
        for i in range(parent.childCount()):
            child = parent.child(i)
            if child.checkState(0) == Qt.Checked:
                self.settings.append(child.text(0))
            if child.childCount() > 0:
                self.collectsettings(child)

'''
    def load_chosen_settings(self, file_path):
        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                chosen_settings = [line.strip() for line in file.readlines()]

            for checkbox in self.scroll_content.findChildren(QCheckBox):
                if checkbox.text() in chosen_settings:
                    checkbox.setChecked(True)

    def apply_settings(self):
        print("Settings applied:")
        for checkbox in self.scroll_content.findChildren(QCheckBox):
        print(f"{checkbox.text()}: {'Checked' if checkbox.isChecked() else 'Unchecked'}")
'''
    
    

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
