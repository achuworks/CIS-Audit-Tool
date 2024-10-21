# Define the path to the directory containing the JSON files
$jsonDirectory = "$PSScriptRoot\Output"

# Define the path for the output JSON file
$outputFile = "$PSScriptRoot\CombinedOutput\CombinedFormattedOutput.json"

# Initialize an empty hashtable to hold the combined output
$combinedOutput = @{}

# Get all JSON files in the specified directory
$jsonFiles = Get-ChildItem -Path $jsonDirectory -Filter *.json

# Loop through each JSON file
foreach ($file in $jsonFiles) {
    Write-Host "Processing file: $($file.Name)"
    
    # Read the JSON content from the file
    $jsonContent = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
    
    # Initialize an empty array to hold the formatted output for this file
    $formattedArray = @()

    # Loop through each key-value pair in the JSON content
    foreach ($key in $jsonContent.PSObject.Properties.Name) {
        # Create a hashtable for each key-value pair
        $formattedItem = @{
            Name  = $key
            Value = $jsonContent.$key
        }
        
        # Add the formatted item to the array
        $formattedArray += $formattedItem
    }

    # Add the formatted array to the combined output using the filename (without extension) as the key
    $filenameWithoutExtension = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
    $combinedOutput[$filenameWithoutExtension] = $formattedArray

    # Remove the individual JSON file after processing
 #   Remove-Item -Path $file.FullName -Force
    Write-Host "Deleted file: $($file.Name)"
}

# Convert the combined output hashtable to JSON and save it to the output file
$combinedOutput | ConvertTo-Json -Depth 10 | Set-Content -Path $outputFile

# Read the JSON content back from the output file
$jsonContent = Get-Content -Path $outputFile -Raw | ConvertFrom-Json

# Create a new ordered dictionary to hold the sorted JSON content
$orderedJson = [ordered]@{}

# Sort the keys alphabetically and add them to the ordered dictionary
$jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
    $orderedJson[$_] = $jsonContent.$_
}

# Convert the ordered dictionary back to JSON
$orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100

# Write the sorted JSON content back to the output file
$orderedJsonJson | Set-Content -Path $outputFile


Write-Host "Combined formatted JSON saved to $outputFile"
