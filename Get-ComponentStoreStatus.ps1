function Get-ComponentStoreStatus {
    <#
    .SYNOPSIS
        Analyze the Component Store
    .DESCRIPTION
        Analyze the Component Store
        Windows server 2022 has StartComponentCleanup as a parameter now for Repair-WindowsImage.
    .INPUTS
        Description of objects that can be piped to the script.
    .OUTPUTS
        Description of objects that are output by the script.
    .EXAMPLE
        Get-ComponentStoreStatus
    .LINK
        Links to further documentation.
    .NOTES
        Detail on what the script does, if this is needed.
    #>
    [CmdletBinding()]
    Param (
    )
    
    begin {
        
    }
    
    process {
    
        try {
            Write-Verbose -Message "Starting Windows Component Store Analyze..."
            $AnalyzeComponentStore = Invoke-Expression "C:\Windows\system32\Dism.exe /Online /Cleanup-Image /AnalyzeComponentStore"

            Write-Verbose -Message "Analyzing Windows Component Store output"
            $ComponentStoreOutput = $AnalyzeComponentStore | Where-Object { $_.contains("Component Store Cleanup Recommended") } |
            Select-Object -Property @{Name = "CleanupRecommended"; Expression = { $_.substring(38, 2) } }

            [PSCustomObject]@{
                Name               = "ComponentStore"
                CleanupRecommended = if ($ComponentStoreOutput.CleanupRecommended -eq "No") { $false } else { $true }
            }
        }
        catch {
            $PSCmdlet.ThrowTerminatingError($PSitem)
        }
    }
    
    end {
    }
}
