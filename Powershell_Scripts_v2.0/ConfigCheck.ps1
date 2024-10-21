# Load the JSON files
$requiredJson = Get-Content -Path "$PSScriptRoot\Required_Config\RequiredDataToCompare.json" -Raw | ConvertFrom-Json
$checkJson = Get-Content -Path "$PSScriptRoot\CombinedOutput\CombinedFormattedOutput.json" -Raw | ConvertFrom-Json

# Function to compare and update combined formatted output
function Compare-Json {
    param (
        [Array]$requiredArray,
        [Array]$sampleArray,
        [String]$sectionName
    )

    # Create an array to hold updated or new items
    $updatedArray = @()

    foreach ($sampleItem in $sampleArray) {
        $requiredItem = $requiredArray | Where-Object { $_.name -eq $sampleItem.name }

        if ($requiredItem) {
            # Add "Priority" field from the requiredJson
            $sampleItem | Add-Member -MemberType NoteProperty -Name "Priority" -Value $requiredItem.Priority -Force

            if ($requiredItem.value -eq $sampleItem.value) {
                $sampleItem | Add-Member -MemberType NoteProperty -Name "Config" -Value "Pass" -Force
            } else {
                $sampleItem | Add-Member -MemberType NoteProperty -Name "Config" -Value "Fail" -Force
            }

            # Add to the updated array
            $updatedArray += $sampleItem
        } else {
            # If the item is not found in the required JSON, add default values
            $sampleItem | Add-Member -MemberType NoteProperty -Name "Priority" -Value "Undefined" -Force
            $sampleItem | Add-Member -MemberType NoteProperty -Name "Config" -Value "Unknown" -Force

            # Add to the updated array
            $updatedArray += $sampleItem
        }
    }

    # Update the section in the combined JSON with the updated array
    $checkJson.$sectionName = $updatedArray
}

# Iterate over each section in the checkJson
$checkJson.PSObject.Properties | ForEach-Object {
    $sectionName = $_.Name
    $checkSection = $checkJson.$sectionName
    $requiredSection = $requiredJson.$sectionName

    if ($requiredSection) {
        Compare-Json -requiredArray $requiredSection -sampleArray $checkSection -sectionName $sectionName
    } else {
        # If the section does not exist in requiredJson, add default values to all items in checkSection
        foreach ($item in $checkSection) {
            $item | Add-Member -MemberType NoteProperty -Name "Priority" -Value "Undefined" -Force
            $item | Add-Member -MemberType NoteProperty -Name "Config" -Value "Unknown" -Force
        }
    }
}

# Save the updated combined formatted output JSON file
$checkJson | ConvertTo-Json -Depth 4 | Set-Content -Path "$PSScriptRoot\CombinedOutput\Updated_CombinedFormattedOutput.json"
