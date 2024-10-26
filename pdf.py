import pandas as pd

csv_file = 'output3.csv'
df = pd.read_csv(csv_file, delimiter='|')

html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report</title>
    <style>
        table {
            width: 80%;
            border-collapse: collapse;
            margin: 25px auto; /* Center table for printing */
            font-size: 18px;
            text-align: left;
        }
        th, td {
            padding: 12px 15px;
            border: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        /* Handling long text */
        td {
            word-wrap: break-word;
            max-width: 300px; /* Adjust as needed */
        }
        h1 {
            margin: 5px auto;
            text-align: center;
            color: red;
            vertical-align: middle;
        }
        img {
            display: block;
            margin-left: auto;
            margin-right: auto;
        }
        @media print {
            body {
                font-size: 12px;
                margin: 0;
                padding: 0;
            }
            h2, h1 {
                text-align: center;
                page-break-after: avoid;
            }
            table {
                width: 100%;
                margin: 0;
                page-break-before: avoid;
                page-break-after: auto;
            }
            tr, td {
                page-break-inside: avoid;
            }
        }
    </style>
</head>
<body>

<h2 style="text-align: center;">Security Report</h2>
<h1>Umbrella Corporation</h1>
<img src="logo.jpg" height="70px" width="100px">
<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Status</th>
            <th>Priority</th>
        </tr>
    </thead>
    <tbody>
"""

for index, row in df.iterrows():
    html += f"""
    <tr>
        <td>{row['Name']}</td>
        <td>{row['Status']}</td>
        <td>{row['Priority']}</td>
    </tr>
    """

# Close the HTML tags
html += """
    </tbody>
</table>
</body>
</html>
"""

# Write the HTML to a file
output_html = 'report.html'
with open(output_html, 'w') as f:
    f.write(html)

print(f"HTML report saved as {output_html}")
