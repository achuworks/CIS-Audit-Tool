import pandas as pd


csv_file = 'rem.csv'
df = pd.read_csv(csv_file, delimiter='|')

df.fillna('', inplace=True)

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
            display: flex;
            justify-content: space-around;
            margin-top: 20px;
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
            background-color: #05b40b;
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
        .a {
            color: green;
        }
        .b {
            color: red;
        }
        .t1 {
            background-color: #05b40b;
        }
        .t2 {
            background-color: red;
        }
        .c{
            color:green;
        }
    </style>
</head>
<body>

<h2>Security Configuration Compliance Report</h2>
<h1>Umbrella Corporation</h1>
<h1>Remediation Report</h1>
<img src="logo.jpg" height="70px" width="100px">

<div class="table-container">

    <div>
        <h2 class="c">After Remediation</h2>
        <table>
            <thead>
                <tr>
                    <th class="t1">Name</th>
                    <th class="t1">Remediation Status</th>
                </tr>
            </thead>
            <tbody>
"""


for index, row in df.iterrows():
    remediation_status = row['RemediationStatus']
    html += f"""
                <tr>
                    <td>{row['Name']}</td>
                    <td>{remediation_status}</td>
                </tr>
    """


html += """
            </tbody>
        </table>
    </div>

</div>

</body>
</html>
"""


output_html = 'remnew.html'
with open(output_html, 'w') as f:
    f.write(html)

print(f"HTML remediation output {output_html}")
