function Optimize-ComponentStore {
    <#
    .SYNOPSIS
        Analyze and cleanup the Component Store
    .DESCRIPTION
        Analyze the Component Store and start a cleanup procedure if it needs it. 
        Windows server 2022 has StartComponentCleanup as a parameter now for Repair-WindowsImage.
    .PARAMETER LogPath
        Path of the logfile you want it to log to. Default is C:\Temp.
    .INPUTS
        Description of objects that can be piped to the script.
    .OUTPUTS
        Description of objects that are output by the script.
    .EXAMPLE
        Optimize-ComponentStore
    .LINK
        Links to further documentation.
    .NOTES
        Detail on what the script does, if this is needed.
    #>
    [CmdletBinding()]
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
        
    }
    
    process {
    
        try {
            
        $logger.Warning("Cleaning Up Windows Component Store")
        Write-Warning -Message "Cleaning Up Windows Component Store"

        $StartComponentCleanup = Invoke-Expression "C:\Windows\system32\Dism.exe /Online /Cleanup-Image /StartComponentCleanup"
        $logger.Informational(" $StartComponentCleanup")

        $StartComponentCleanup
        
        }
        catch {
            $logger.Error("$PSitem")
            $PSCmdlet.ThrowTerminatingError($PSitem)
        }
    }
    
    end {
        $logger.Notice("Finished $($MyInvocation.MyCommand) script")        
    }
}
