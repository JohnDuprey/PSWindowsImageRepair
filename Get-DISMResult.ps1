function Get-DISMResult {
    <#
    .SYNOPSIS
        Obtain part of the dism results.
    .DESCRIPTION
        Grab the last 500 lines of the dism log file and if any keywords are applied then filter for those.
    .PARAMETER Path
        Path to the DISM log file.
    .PARAMETER KeyWord
        Keyword you wish to look/filter for.
    .INPUTS
        Description of objects that can be piped to the script.
    .OUTPUTS
        Description of objects that are output by the script.
    .EXAMPLE
        Get-DISMResult
    .LINK
        https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/deployment-troubleshooting-and-log-files?view=windows-10#offline-servicing-related-log-files
    .NOTES
        Detail on what the script does, if this is needed.
    #>
    [CmdletBinding()]
    Param (
        # Param1 help description
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
        $Path = "$env:SystemRoot\Logs\DISM\dism.log",

        [Parameter(
            Position = 1,
            ValueFromPipeline)]
        [ValidateSet("Success", "Warning", "Fail", "Error", "Finished", "Info")]
        $KeyWord
    )
    
    begin {

        # First block to add/change stuff in
        try {
            $result = Get-Content -Path $Path -Tail 500
        }
        catch {
            $PSCmdlet.ThrowTerminatingError($PSitem)
        }
        
    }
    
    process {
    
        try {
            if ($PSBoundParameters.ContainsKey('KeyWord')) {
                $result | Select-String $KeyWord
            } else {
                $result
            }
        }
        catch {
            $PSCmdlet.ThrowTerminatingError($PSitem)
        }
    }
    
    end {
        
    }
}