# Define the path for the JSON and CSV files
$jsonFile = "$PSScriptRoot\CombinedOutput\Updated_CombinedFormattedOutput.json"
$csvFilePath = "$PSScriptRoot\CombinedOutput\CombinedResult.csv"

# Read the JSON content
$jsonContent = Get-Content -Path $jsonFile | Out-String | ConvertFrom-Json

# Initialize an array to hold the CSV lines
$csvLines = @()

# Add header line to the CSV
$csvLines += "Category|Name|Value|Priority|Configuration"

# Convert each section of the JSON to CSV format
foreach ($section in $jsonContent.PSObject.Properties.Name) {
    foreach ($item in $jsonContent.$section) {
        # Create a CSV line for each item
        $csvLine = "$section|$($item.name)|$($item.value)|$($item.Priority)|$($item.Config)"
        $csvLines += $csvLine
    }
}

# Write the CSV content to the file without quotes
Set-Content -Path $csvFilePath -Value $csvLines
