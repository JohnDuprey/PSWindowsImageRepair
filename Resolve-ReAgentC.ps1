function Resolve-ReAgentC {
    <#
    .SYNOPSIS
        Enables Windows recovery if not already.
    .DESCRIPTION
        Sets a couple of session variables and parses "ReagentC.exe /info" output. If the system is not already enabled this
        will start to set the system up so it can be enabled and removes any extra recovery partitions that are not
        in use so it can find the correct one.
    .PARAMETER LogPath
        Path of the logfile you want it to log to. Default is C:\Temp.
    .INPUTS
        Description of objects that can be piped to the script.
    .OUTPUTS
        WindowsRecoveryStatus object, either enabled or disabled.
    .EXAMPLE
        Resolve-ReAgentC
    .LINK
        https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/reagentc-command-line-options?view=windows-11
    .NOTES
        Detail on what the script does, if this is needed.
    #>
    [CmdletBinding(ConfirmImpact='High')]

    Param (        
        [Parameter(
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [String]$LogPath = "C:\Temp"
    )
    
    begin {
        # Add Logging block
        try {
            if (!("PSLogger" -as [type])) {
                $callingScript = ($MyInvocation.MyCommand.Name) -split ('.ps1')
                ."\\server\path\here\Logging.ps1"
                $logger = [PSLogger]::new($LogPath, $callingScript)
            }
        }
        catch {
            $PSCmdlet.ThrowTerminatingError($PSitem)
        }
    
        $logger.Notice("Starting $($MyInvocation.MyCommand) script")

        # First block to add/change stuff in
        try {
            Write-Verbose -Message "Setting Error Action to Silently Continue"
            $ErrorActionPreference = "SilentlyContinue"

            Write-Verbose -Message "Creating and setting a environment variable for $([Environment]::SystemDirectory)"
            $env:SystemDirectory = [Environment]::SystemDirectory
            $xml = "$env:SystemDirectory\Recovery\ReAgent.xml"

            $logger.Informational("Checking Windows Recovery Environment info...")
            Write-Verbose -Message "Checking Windows Recovery Environment info..."
    
            $analyzeReagentc = Invoke-Expression "$env:SystemDirectory\ReagentC.exe /info"   
            $analyzeReagentcEnabled = "$AnalyzeReagentC" -Match [regex]::new("Enabled")
            $analyzeReagentcDisabled = "$AnalyzeReagentC" -Match [regex]::new("Disabled")
    
        }
        catch {
            $logger.Error("$PSitem")
            $PSCmdlet.ThrowTerminatingError($PSitem)
        }
        
    }
    
    process {
    
        try {
            
            if ($analyzeReagentcEnabled) {
                $logger.informational("Windows RE Status: Enabled")
                $Status = "Enabled"
            }
            elseif ($analyzeReagentcDisabled) {
                $Status = "Disabled"
                Write-Verbose -Message "Enabling Windows Recovery Environment"
                if (Test-Path -Path $xml) {
                    $logger.warning("Removing $xml")
                    Remove-Item -Path $xml
                }
                $enableWinRE = Invoke-Expression "$env:SystemDirectory\ReagentC.exe /enable"
                $Status = "Enabled"

            }
            else {
                $logger.warning("Unknown Windows RE Status")
                $Status = "Unknown"
            }
    
        }
        catch {
            $logger.Error("$PSitem")
            $PSCmdlet.ThrowTerminatingError($PSitem)
        }

        try {
            $Partition = (Get-Partition -DiskNumber 0 | Where-Object {$_.type -match "Recovery"})
            if ($Partition.count -gt 1) {

                [string]$recoveryPartition = $analyzeReagentc | select-string -pattern "partition"

                if(!([string]::IsNullOrWhiteSpace($recoveryPartition))){

                    if($recoveryPartition -match '(partition+\d)') {

                        $logger.informational("$($matches[0]) is the current recovery partition, removing non-used recovery partition")
                        Write-output "$($matches[0]) is the current recovery partition, removing non-used recovery partition"

                        if($matches[0] -match'(\d)') {
                            $Partition | Where-Object {$_.PartitionNumber -notcontains "$($matches[0])"} | Remove-Partition
                            $logger.informational("Removed non-used recovery partition")
                        }

                    }

                }
            } 
        }
        catch {
            $logger.Error("$PSitem")
            $PSCmdlet.ThrowTerminatingError($PSitem)
        }

        [PSCustomObject]@{
            WindowsRecoveryStatus = $Status
        }
    }
    
    end {
        $logger.Notice("Finished $($MyInvocation.MyCommand) script")
        
    }
}