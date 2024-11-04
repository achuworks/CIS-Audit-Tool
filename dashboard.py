from PySide6.QtWidgets import QApplication, QWidget, QLabel, QVBoxLayout, QHBoxLayout, QGridLayout, QPushButton, QGroupBox, QScrollArea
from PySide6.QtCharts import QChart, QChartView, QPieSeries, QLineSeries
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtGui import QPainter
import sys, csv

class Dashboard(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("CIS Benchmark Dashboard")
        self.setGeometry(100, 100, 1200, 700)

        main_layout = QVBoxLayout()
        grid_layout = QGridLayout()

        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        self.currently_visible_description = None

        passed_count, failed_count, high_count, medium_count, low_count = self.calculate_counts()

        # Display "TOTAL PASSED" indicator
        grid_layout.addWidget(self.create_indicator(f"TOTAL PASSED: {passed_count}", "#008000"), 0, 0, 1, 2)

        # Display "TOTAL FAILED" indicator with colored severities in a single line
        failed_widget = self.create_failed_indicator(failed_count, high_count, medium_count, low_count)
        grid_layout.addWidget(failed_widget, 0, 2, 1, 2)

        pie_chart_view = self.create_pie_chart(high_count, medium_count, low_count)
        pie_chart_view.setFixedSize(400, 300)
        grid_layout.addWidget(pie_chart_view, 1, 3, 1, 1)

        line_chart_view = self.create_line_chart()
        line_chart_view.setFixedSize(400, 300)
        grid_layout.addWidget(line_chart_view, 2, 3, 1, 1)
        self.setStyleSheet("QWidget{background-color:#FFFFFF}")

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)

        with open("output3.csv", "r") as file:
            creader = csv.reader(file, delimiter='|')
            next(creader)
            for row in creader:
                name, status, status_to_be, priority, registry_value, value_to_be = row

                group_box = QGroupBox(name)
                group_box.setStyleSheet("border: none;")
                group_layout = QVBoxLayout()

                button = QPushButton(name)
                button.setStyleSheet("QPushButton{color: black; border: 1px solid grey;border-radius:15px;padding:5px;margin:2px}")
                button.clicked.connect(lambda checked, gb=group_box: self.toggle_visibility(gb))

                description = f"Status: {status} | Status To Be: {status_to_be}"
                description_label = QLabel(description)
                description_label.setWordWrap(True)
                description_label.setStyleSheet("color: black; font-size: 13px;border: 1px solid grey;background-color:#bfbfbf;border-radius:15px;padding:5px")
                description_label.setVisible(False)

                group_layout.addWidget(button)
                group_layout.addWidget(description_label)
                group_box.setLayout(group_layout)
                scroll_layout.addWidget(group_box)

        scroll_area.setWidget(scroll_content)
        grid_layout.addWidget(scroll_area, 1, 0, 2, 3)

        main_layout.addLayout(grid_layout)
        self.setLayout(main_layout)

    def calculate_counts(self):
        passed_count = 0
        failed_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0

        with open("output3.csv", "r") as file:
            creader = csv.reader(file, delimiter='|')
            next(creader)
            for row in creader:
                _, status, status_to_be, priority, _, _ = row

                if status == status_to_be:
                    passed_count += 1
                else:
                    failed_count += 1

                    if priority == "HIGH":
                        high_count += 1
                    elif priority == "MEDIUM":
                        medium_count += 1
                    elif priority == "LOW":
                        low_count += 1

        return passed_count, failed_count, high_count, medium_count, low_count

    def create_indicator(self, text, color):
        layout = QVBoxLayout()
        lbl = QLabel(text)
        lbl.setStyleSheet(f"font-size: 20px; color: {color}; margin:0px; padding:0px")
        lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(lbl)
        widget = QWidget()
        widget.setLayout(layout)
        return widget

    def create_failed_indicator(self, failed_count, high_count, medium_count, low_count):
        layout = QVBoxLayout()

        lbl_failed = QLabel(f"TOTAL FAILED: {failed_count}")
        lbl_failed.setStyleSheet("font-size: 20px; color: #8B0000;")
        lbl_failed.setAlignment(Qt.AlignCenter)
        layout.addWidget(lbl_failed)

        severity_layout = QHBoxLayout()

        lbl_high = QLabel(f"HIGH: {high_count}")
        lbl_high.setStyleSheet("font-size: 15px; color: #FF0000;") 
        severity_layout.addWidget(lbl_high)

        lbl_medium = QLabel(f"MEDIUM: {medium_count}")
        lbl_medium.setStyleSheet("font-size: 15px; color: #FFA500;")  
        severity_layout.addWidget(lbl_medium)

        lbl_low = QLabel(f"LOW: {low_count}")
        lbl_low.setStyleSheet("font-size: 15px; color: #0000FF;")  
        severity_layout.addWidget(lbl_low)

        severity_widget = QWidget()
        severity_widget.setLayout(severity_layout)
        severity_layout.setAlignment(Qt.AlignCenter)

        layout.addWidget(severity_widget)

        widget = QWidget()
        widget.setLayout(layout)
        return widget

    def create_pie_chart(self, high_count, medium_count, low_count):
        # Create the pie chart series and add each severity count
        series = QPieSeries()
        series.append("High", high_count)
        series.append("Medium", medium_count)
        series.append("Low", low_count)

        high_slice = series.slices()[0]
        high_slice.setBrush(Qt.red)
        high_slice.setLabelVisible(True)
        high_slice.setLabel(f"High: {high_count}")

        medium_slice = series.slices()[1]
        medium_slice.setBrush(QColor(255, 191, 0))

        medium_slice.setLabelVisible(True)
        medium_slice.setLabel(f"Medium: {medium_count}")

        low_slice = series.slices()[2]
        low_slice.setBrush(Qt.blue)
        low_slice.setLabelVisible(True)
        low_slice.setLabel(f"Low: {low_count}")

        chart = QChart()
        chart.addSeries(series)
        chart.setTitle("CIS Benchmark Severity Distribution")
        chart.legend().setAlignment(Qt.AlignRight)

        chart_view = QChartView(chart)
        chart_view.setRenderHint(QPainter.Antialiasing)
        return chart_view

    def create_line_chart(self):
        series = QLineSeries()
        series.append(0, 1)
        series.append(1, 3)
        series.append(2, 2)
        series.append(3, 5)
        series.append(4, 4)

        chart = QChart()
        chart.addSeries(series)
        chart.createDefaultAxes()
        chart.setTitle("CIS Benchmark Over Time")

        chart_view = QChartView(chart)
        chart_view.setRenderHint(QPainter.Antialiasing)
        return chart_view

    def toggle_visibility(self, group_box):
        if self.currently_visible_description and self.currently_visible_description != group_box:
            for i in range(self.currently_visible_description.layout().count()):
                widget = self.currently_visible_description.layout().itemAt(i).widget()
                if isinstance(widget, QLabel):
                    widget.setVisible(False)

        for i in range(group_box.layout().count()):
            widget = group_box.layout().itemAt(i).widget()
            if isinstance(widget, QLabel):
                widget.setVisible(not widget.isVisible())

        self.currently_visible_description = group_box

if __name__ == "__main__":
    app = QApplication(sys.argv)
    dashboard = Dashboard()
    dashboard.show()
    sys.exit(app.exec())
