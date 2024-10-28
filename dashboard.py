from PySide6.QtWidgets import QApplication, QWidget, QLabel, QVBoxLayout, QGridLayout, QPushButton, QGroupBox, QScrollArea
from PySide6.QtCharts import QChart, QChartView, QPieSeries, QLineSeries
from PySide6.QtCore import Qt
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

     
        grid_layout.addWidget(self.create_indicator("849", "HIGH", "#FF0000"), 0, 0)  
        grid_layout.addWidget(self.create_indicator("384", "MEDIUM", "#FFA500"), 0, 1)  
        grid_layout.addWidget(self.create_indicator("31", "LOW", "#0000FF"), 0, 2)     

     
        pie_chart_view = self.create_pie_chart()
        pie_chart_view.setFixedSize(400, 300)
        grid_layout.addWidget(pie_chart_view, 1, 3, 1, 1)

        line_chart_view = self.create_line_chart()
        line_chart_view.setFixedSize(400, 300)
        grid_layout.addWidget(line_chart_view, 2, 3, 1, 1)
        self.setStyleSheet("QWidget{background-color:#FFFFFF}");

        white = QWidget()
        white.setStyleSheet("background-color:white")
        grid_layout.addWidget(white, 0, 3, 1, 1)

        
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)

        with open("output.txt", "r") as file:
            creader = csv.reader(file)
            for i in creader:
                group_box = QGroupBox(i[0])
                group_box.setStyleSheet("border: none;")
                group_layout = QVBoxLayout()

                button = QPushButton(i[0])
                button.setStyleSheet("QPushButton{color: black; border: 1px solid grey;border-radius:15px;padding:5px;margin:2px}")
                button.clicked.connect(lambda checked, gb=group_box: self.toggle_visibility(gb))

                description_label = QLabel(i[1])
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

    def create_indicator(self, value, label, color):
        layout = QVBoxLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        lbl_value = QLabel(value)
        lbl_value.setStyleSheet(f"font-size: 30px; color: {color};margin:0px;padding:0px")
        lbl_value.setAlignment(Qt.AlignCenter)

        lbl_label = QLabel(label)
        lbl_label.setStyleSheet(f"font-size: 15px; color: {color};margin:0px;padding:0px")
        lbl_label.setAlignment(Qt.AlignTop | Qt.AlignHCenter)

        layout.addWidget(lbl_value)
        layout.addWidget(lbl_label)

        widget = QWidget()
        widget.setLayout(layout)
        return widget

    def create_pie_chart(self):
        series = QPieSeries()
        series.append("High", 20)
        series.append("Medium", 30)
        series.append("Low", 40)

        chart = QChart()
        chart.addSeries(series)
        chart.setTitle("CIS Benchmark Severity")
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
