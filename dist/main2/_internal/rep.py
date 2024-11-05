import pandas as pd
import webbrowser
import os


csv_file = 'output3.csv'
df = pd.read_csv(csv_file, delimiter='|')

df.fillna('', inplace=True)

priority_map = {
    'HIGH': 1,
    'MEDIUM': 2,
    'LOW': 3
}
status_map = {
    'NOT ENABLED': 1,
    'NOT SET': 2,
    'ENABLED': 3
}

df['PrioritySort'] = df['Priority'].str.upper().map(priority_map)
df['StatusSort'] = df['Status'].str.upper().map(status_map)

df.sort_values(by=['PrioritySort', 'StatusSort'], inplace=True)

html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Configuration Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f9f9f9;
        }
        .table-container {
            margin: 20px auto;
            width: 90%;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 18px;
            text-align: left;
            background-color: #fff;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }
        th, td {
            padding: 12px 15px;
            border: 1px solid #ddd;
        }
        th {
            background-color: black;
            color: white;
        }
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        tr:hover {
            background-color: #ddd;
        }
        td {
            word-wrap: break-word;
            max-width: 300px;
        }
        h1, h2 {
            text-align: center;
            color: #333;
        }
        h1 {
            margin-top: 15px;
            font-size: 28px;
            color: #750202;
        }
        h2 {
            margin-bottom: 5px;
            font-size: 24px;
        }
        img {
            display: block;
            margin: 0 auto;
        }
        .high {
            color: black;
            background-color: rgb(255, 0, 0);  
            font-weight: 700;
        }
        .medium {
            color: black;
            background-color: rgb(255, 166, 0); 
            font-weight: 700;
        }
        .low {
            color: black;
            background-color: rgb(27, 92, 233); 
            font-weight: 700;
        }
        .header {
            background-color: #05b40b;
        }
        .sub-header {
            background-color: #e0e0e0;
            font-weight: bold;
            text-align: center;
        }
        .status-match {
            background-color: rgb(6, 130, 6); /* Dark Green for match */
            color: white;
            font-weight: bold;
        }
        .status-mismatch {
            background-color: rgb(200, 0, 0); /* Dark Red for mismatch */
            color: white;
            font-weight: bold;
        }
        .row-match {
            background-color: rgb(200, 255, 200); /* Light Green for row match */
        }
        .row-mismatch {
            background-color: rgb(255, 200, 200); /* Light Red for row mismatch */
        }
    </style>
</head>
<body>

<h2>Security Configuration Compliance Report</h2>
<h1>Umbrella Corporation</h1>
<img src="logo.jpg" height="70px" width="100px">

<div class="table-container">
    <table>
        <thead>
            <tr class="header">
                <th>Name</th>
                <th>Your Status</th>
                <th>Status as per (CIS)</th>
                <th>Priority</th>
                <th>Your Registry Value</th>
                <th>ValueToBe</th>
            </tr>
        </thead>
        <tbody>
"""


for index, row in df.iterrows():
    priority_class = ""
    if 'HIGH' in row['Priority'].strip().upper():
        priority_class = "high"
    elif 'MEDIUM' in row['Priority'].strip().upper():
        priority_class = "medium"
    elif 'LOW' in row['Priority'].strip().upper():
        priority_class = "low"
  
    row_class = "row-match" if row['Status'].strip().upper() == row['StatusToBe'].strip().upper() else "row-mismatch"
    status_class = "status-match" if row['Status'].strip().upper() == row['StatusToBe'].strip().upper() else "status-mismatch"
    
    html += f"""
    <tr class="{row_class}">
        <td>{row['Name']}</td>
        <td class="{status_class}">{row['Status']}</td>
        <td>{row['StatusToBe']}</td>
        <td class="{priority_class}">{row['Priority']}</td>
        <td>{row['RegistryValue']}</td>
        <td>{row['ValueToBe']}</td>
    </tr>
    """

html += """
        </tbody>
    </table>
</div>

</body>
</html>
"""

output_html = 'merged_report.html'
with open(output_html, 'w') as f:
    f.write(html)

webbrowser.open(f'file://{os.path.realpath(output_html)}')

print(f"Merged HTML report with color-coded rows and 'Your Status' cell saved as {output_html} and opened in browser.")
