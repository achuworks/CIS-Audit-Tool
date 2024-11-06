import subprocess
import os
import pandas as pd
import json
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QMainWindow, QScrollArea, QPushButton, QGridLayout, QListWidget, QHBoxLayout, QTreeWidget, QTreeWidgetItem, QFileDialog
)
from PySide6.QtCore import Qt
import sys

os_name = sys.argv[1]

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
        
        if("Windows" in os_name):
            with open('config/windows_enterprise.json') as file:
                file_content = file.read()
        elif("Ubuntu" in os_name):
            with open('config/linux_configuration.json') as file:
                file_content = file.read()
        json_data = json.loads(file_content)

        self.tree = SettingsTree(json_data)
        
        self.scroll_layout.addWidget(self.tree)
        self.tree.itemChanged.connect(self.update_chosen_settings)


        self.main_layout.addWidget(self.scroll_area, 2, 0)

        self.chosen_settings_label = QLabel("Chosen Settings", self)
        self.chosen_settings_label.setAlignment(Qt.AlignCenter)
        self.chosen_settings_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #333;")
        self.main_layout.addWidget(self.chosen_settings_label, 1, 1)

        self.chosen_settings_list = QListWidget()
        self.chosen_settings_list.setStyleSheet("background-color: #f0f0f0; font-size: 14px; color: #333;")
        self.main_layout.addWidget(self.chosen_settings_list, 2, 1)

        self.apply_button = QPushButton("Next")
        self.apply_button.setStyleSheet("font-size: 16px; padding: 10px; background-color: #e0e0e0;")
        self.apply_button.clicked.connect(self.next)

        self.import_button = QPushButton("Import")
        self.import_button.setStyleSheet("font-size: 16px; padding: 10px; background-color: #e0e0e0;")
        self.import_button.clicked.connect(self.import_settings)

        self.export_button = QPushButton("Export")
        self.export_button.setStyleSheet("font-size: 16px; padding: 10px; background-color: #e0e0e0;")
        self.export_button.clicked.connect(self.export_settings)

        self.button_layout = QHBoxLayout()
        self.button_layout.addWidget(self.import_button)
        self.button_layout.addWidget(self.export_button)
        self.button_layout.addWidget(self.apply_button)

        self.main_layout.addLayout(self.button_layout, 3, 0, 1, 2)
       
    def run_script(self):
        pass

    def update_chosen_settings(self):
        self.chosen_settings_list.clear()
        self.collect_checked_items(self.tree.invisibleRootItem())

    def collect_checked_items(self,parent): 
        for i in range(parent.childCount()):
            child = parent.child(i)
            if(child.checkState(0) == Qt.Checked):
                self.chosen_settings_list.addItem(child.text(0))
            if(child.childCount() > 0):
                self.collect_checked_items(child)

    def next(self):
        settings = {}
        # Collect settings from the tree structure
        self.collect_settings(self.tree.invisibleRootItem(), settings)

        # Initialize the temporary output file
        temp_output_path = "temp_output.csv"
        subprocess.run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', 'Remove-Item "temp_output.csv" -ErrorAction SilentlyContinue'])

        # Run the initial PowerShell command
        subprocess.run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', '. .\\test.ps1'], check=True)

        # Loop through each setting and run the PowerShell command for each value
        for category, values in settings.items():
            for value in values:
                command = f'. .\\test.ps1; {value}'  # Build the PowerShell command
                subprocess.run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', command], check=True)

        # Call additional commands
        subprocess.run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', '. .\\test.ps1; SayHello'], check=True)

        # Read the temporary output file into a DataFrame
        if os.path.exists(temp_output_path):
            results_df = pd.read_csv(temp_output_path, delimiter='|')
            results_df.to_csv("output.csv", index=False, sep='|')  # Export final results to your output CSV

        # Clean up temporary file
        if os.path.exists(temp_output_path):
            os.remove(temp_output_path)

        os.startfile('main2.py')
        sys.exit()
        
    def export_settings(self):
        settings = {}
        self.collect_settings(self.tree.invisibleRootItem(), settings)
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Settings", "", "JSON Files (*.json)")
        if file_name:
            with open(file_name, 'w') as f:
                json.dump(settings, f, indent=2)

    def import_settings(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Load Settings", "", "JSON Files (*.json)")
        if file_name:
            with open(file_name, 'r') as f:
                settings = json.load(f)
            self.apply_imported_settings(settings)

    def collect_settings(self, parent, settings):
        for i in range(parent.childCount()):
            child = parent.child(i)
            if child.childCount() > 0:
                category = child.text(0)
                settings[category] = []
                for j in range(child.childCount()):
                    grandchild = child.child(j)
                    if grandchild.checkState(0) == Qt.Checked:
                        settings[category].append(grandchild.text(0))
            elif child.checkState(0) == Qt.Checked:
                category = parent.text(0)
                if category not in settings:
                    settings[category] = []
                settings[category].append(child.text(0))

    def apply_imported_settings(self, settings):
        for i in range(self.tree.topLevelItemCount()):
            category_item = self.tree.topLevelItem(i)
            category = category_item.text(0)
            if category in settings:
                for j in range(category_item.childCount()):
                    child = category_item.child(j)
                    if child.text(0) in settings[category]:
                        child.setCheckState(0, Qt.Checked)
                    else:
                        child.setCheckState(0, Qt.Unchecked)
            else:
                for j in range(category_item.childCount()):
                    category_item.child(j).setCheckState(0, Qt.Unchecked)
        self.update_chosen_settings()

class SettingsTree(QTreeWidget):
    def __init__(self,data):
        super().__init__()
        self.setHeaderHidden(True)  # Hide header
        self.setStyleSheet("""QTreeWidget::indicator:unchecked { 
                           border: 1px solid black; background-color: white; border-radius: 5px;
                            }    """)
        # Load JSON data into tree widget
        self.load_json_data(data)

        # Handle clicks on items
        self.itemClicked.connect(self.handle_item_click)

    def load_json_data(self, data):
        for parent, children in data.items():
            parent_item = QTreeWidgetItem([parent])
            parent_item.setCheckState(0, Qt.Unchecked) 
            self.addTopLevelItem(parent_item)

            for child in children:
                child_item = QTreeWidgetItem([child])
                child_item.setCheckState(0, Qt.Unchecked)
                parent_item.addChild(child_item)

    def handle_item_click(self, item, column):
        if item.childCount() > 0: 
            if item.checkState(0) == Qt.Checked:  # Checked
                self.set_children_check_state(item, Qt.Checked)
            else:  # Unchecked
                self.set_children_check_state(item, Qt.Unchecked)
        else:  # If the clicked item is a child
            self.update_parent_state(item)

    def set_children_check_state(self, parent_item, state):
        for i in range(parent_item.childCount()):
            child_item = parent_item.child(i)
            child_item.setCheckState(0, state)

    def update_parent_state(self, child_item):
        parent_item = child_item.parent()
        if parent_item:
            all_checked = True
            all_unchecked = True
            for i in range(parent_item.childCount()):
                sibling_item = parent_item.child(i)
                if sibling_item.checkState(0) == Qt.Checked:
                    all_unchecked = False
                else:
                    all_checked = False

            if all_checked:
                parent_item.setCheckState(0, Qt.Checked)  # Check parent
            elif all_unchecked:
                parent_item.setCheckState(0, Qt.Unchecked)  # Uncheck parent
            else:
                parent_item.setCheckState(0, Qt.PartiallyChecked)  # Partially checked

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

