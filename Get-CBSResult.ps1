function Get-CBSResult {
    <#
    .SYNOPSIS
        Output the results of scanning the CBS log.
    .DESCRIPTION
        Output the results of scanning the CBS log.
    .PARAMETER Path
        Path to the CBS log file.
    .INPUTS
        Description of objects that can be piped to the script.
    .OUTPUTS
        Description of objects that are output by the script.
    .EXAMPLE
        Get-CBSResult
    .LINK
        Links to further documentation.
    .NOTES
        Detail on what the script does, if this is needed.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(
            Position = 0,
            ValueFromPipeline)]
        [ValidateScript( {
                if (-Not ($_ | Test-Path) ) {
                    throw "File does not exist"
                }
                if (-Not ($_ | Test-Path -PathType Leaf) ) {
                    throw "The Path argument must be a file. Folder paths are not allowed."
                }
                if ($_ -notmatch "(\.log)") {
                    throw "The file specified in the path argument must be log"
                }
                return $true 
            })]
        $Path = "$env:SystemRoot\Logs\CBS\CBS.log"
    )
    
    begin {

        # First block to add/change stuff in
        try {
            # CBS keywords
            $restoreKeywords = @(
                "Total Detected",
                "Manifest Corruption",
                "Metadata Corruption",
                "Payload Corruption",
                "Total Repaired",
                "Manifest Repaired",
                "Payload Repaired",
                "Total Operation"
            )

            # Scan Array
            $scans = @(
                @{boolean = "\[SR\]" ; date = "[SR]" ; keyword = "[SR]" },
                @{boolean = "Manifest Corruption" ; date = "Manifest Corruption" ; keyword = $restoreKeywords }
            )
        }
        catch {
            $PSCmdlet.ThrowTerminatingError($PSitem)
        }
        
    }
    
    process {
    
        try {
            Write-Verbose -Message "Scanning CBS Log File.."

            foreach ($scan in $scans) {
                # Reuse Variable to grab cbs content
                $csbPath = Get-Content "$Path"

                # Checks to see if a scan was run at all for the item
                $ScanBoolean = if ($csbPath | Where-Object { $_ -match "$($scan.Boolean)" } | Select-Object -First 1) { "TRUE" } else { "FALSE" }
        
                if ($ScanBoolean -eq $True) {
                    # Outputs the restore scan lines with last checkdate
                    $dateScan = $csbPath | Where-Object { $_.Contains("$($scan.date)") } | 
                    Select-Object -Property @{Name = "LastCheckDate"; Expression = { $_.substring(0, 10) } } -Last 1
        
                    # Filter out the known good lines and get only the interesting lines
                    foreach ($keyword in $($scan.keyword)) {
                        $csbPath | Where-Object { $_.Contains("$keyword") -and $_.Contains($dateScan.lastcheckdate) } | 
                        Select-String -NotMatch "Verify complete", "Verifying", "Beginning Verify and Repair" #*>&1
                    }
                }
            }
        
        }
        catch {
            $PSCmdlet.ThrowTerminatingError($PSitem)
        }
    }
    
    end {
        
    }
}