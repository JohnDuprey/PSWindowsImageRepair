function Repair-Image {
    <#
    .SYNOPSIS
        Repairs an image
    .DESCRIPTION
        This script will validate the path given for a local repair source and make sure it exists, type, and extension meets requirements first.
        Then it will test to see if the CSB log file is locked, if it is then it will unlock it. Once unlocked, if it hasn't refreshed in 
        the last 5 minutes then it will delete the current CBS log and refresh it.
        When it has completed it will then parse the log file to see what has been fixed and show the results on the screen.

        It will then test and fix the ReagentC xml file and resolve component store items as needed.
        A Online health check will then kick off to check for corruption, if it passes the script finishes. If it fails, it continues on to check the internet connection. 
        If 5% and below for packet loss then it will pull an image from Microsoft to fix component store corruption and log it to "C:\RestoreHealth.log".
        If the internet connection is bad then it can use a network stored image or locally stored image path. It will mount, index, and convert
        the image and try to repair windows using it. Logs will go to "C:\RepairLogs"
    .PARAMETER Path
        Give a path for a ISO,WIM,ESD on a USB drive or drive local to the computer
    .PARAMETER AcceptableRate
        The allowable percentage of packets dropped
    .PARAMETER CBSPath
        Where the cbspath is being logged
    .PARAMETER CBSLifeSpan
        How long the since the file was last created before needing to be deleted.
    .PARAMETER LogPath
        Path of the logfile you want it to log to. Default is C:\Temp.
    .PARAMETER UseSource
       Switch that enables or disables the needed use of ISO,WIM,ESD files instead of online fix.
    .INPUTS
        Description of objects that can be piped to the script.
    .OUTPUTS
        Description of objects that are output by the script.
    .EXAMPLE
        Repair-Image -Path "$home\desktop\win10.iso"
    .EXAMPLE
        Repair-Image -Path "\\server\path\install.wim"
    .EXAMPLE
        Repair-Image -AcceptableRate 75
    .EXAMPLE
        Repair-Image -CBSLifeSpan -10
    .EXAMPLE
        Repair-Image -UseSource
    .EXAMPLE
        Repair-Image -Path "$home\desktop\win10.iso","\\server\path\install.wim" -AcceptableRate 75 -CBSLifeSpan -10 -UseSource
    .LINK
        Links to further documentation.
    .NOTES
        #Dism /Online /Cleanup-Image /RestoreHealth /Source:esd:C:\$Windows.~BT\Sources\Install.esd:1 /limitaccess
        #Dism /Online /Cleanup-Image /RestoreHealth /Source:wim:D:\sources\install.wim:1 /limitaccess
    #>
    [CmdletBinding()]
    param (
        [Parameter(
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript( {
                if (-Not ($_ | Test-Path) ) {
                    throw "File does not exist"
                }
                if (-Not ($_ | Test-Path -PathType Leaf) ) {
                    throw "The Path argument must be a file. Folder paths are not allowed."
                }
                if ($_ -notmatch "(\.wim|\.esd|\.iso)") {
                    throw "The file specified in the path argument must be either of type wim, esd, or iso"
                }
                return $true 
            })]
        [string[]]$Path,

        [Parameter()]
        [ValidateRange(70, 95)]
        [int]$AcceptableRate = "95.00",

        [Parameter()]
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
        [System.IO.FileInfo]$CBSPath = "$env:SystemRoot\Logs\CBS\CBS.log",

        [Parameter()]
        [ValidateRange(0, 9999)]
        [int]$CBSLifeSpan = -5,

        [Parameter(
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [String]$LogPath = "C:\Temp",

        [Parameter()]
        [switch]$UseSource
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

        try {
            $scriptTimer = [Diagnostics.Stopwatch]::StartNew()

            $imageType = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            if ($imageType.InstallationType -match "Client") {
                $winProductName = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName
            } else {
                $winProductName = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name EditionID).EditionID
            }

            $logLevel = @{
                LogLevel = "WarningsInfo"
                LogPath  = "$LogPath\RestoreHealth.log"
            }

            $repairParams = @{
                Online = $True
                RestoreHealth = $True
                LimitAccess = $True
                ErrorAction = "Stop"
            }

        }
        catch {
            $PSCmdlet.ThrowTerminatingError($PSitem)
        }

        try {
            function Get-SFCResult {
                <#
                .SYNOPSIS
                    Get SFC results and output to an object
                .DESCRIPTION
                    Get SFC output and create an object with information for current state and matching description
                .PARAMETER FirstParameter
                    Description of each of the parameters.
                    Note:
                    To make it easier to keep the comments synchronized with changes to the parameters,
                    the preferred location for parameter documentation comments is not here,
                    but within the param block, directly above each parameter.
                .PARAMETER SecondParameter
                    Description of each of the parameters.
                .INPUTS
                    Description of objects that can be piped to the script.
                .OUTPUTS
                    Description of objects that are output by the script.
                .EXAMPLE
                    Get-SFCResult
                .EXAMPLE
                    $result = Get-SFCResult
                    $result | Where-Object {$PSItem.bool -eq $true}
                .LINK
                    Links to further documentation.
                .NOTES
                    Detail on what the script does, if this is needed.
                #>
                [CmdletBinding()]
                Param (       

                )
                
                begin {

                    # First block to add/change stuff in
                    try {

                        $serviceRequired = @(
                            "W.i.n.d.o.w.s...R.e.s.o.u.r.c.e...P.r.o.t.e.c.t.i.o.n...c.o.u.l.d...n.o.t...s.t.a.r.t...t.h.e...r.e.p.a.i.r...s.e.r.v.i.c.e"
                        )

                        # Output of successful repairs or checks
                        $clean = @(
                            "f.o.u.n.d...c.o.r.r.u.p.t...f.i.l.e.s...a.n.d...s.u.c.c.e.s.s.f.u.l.l.y...r.e.p.a.i.r.e.d...t.h.e.m.",
                            "d.i.d...n.o.t...f.i.n.d...a.n.y...i.n.t.e.g.r.i.t.y...v.i.o.l.a.t.i.o.n.s.",
                            "T.h.e...c.o.m.p.o.n.e.n.t...s.t.o.r.e...i.s...r.e.p.a.i.r.a.b.l.e"
                        )

                        # Image could not be repaired
                        $corrupted = @(
                            "c.o.r.r.u.p.t...f.i.l.e.s...b.u.t...w.a.s...u.n.a.b.l.e...t.o...f.i.x...s.o.m.e...o.f...t.h.e.m.",
                            "T.h.e...s.o.u.r.c.e...f.i.l.e.s...c.o.u.l.d...n.o.t...b.e...f.o.u.n.d."
                        )

                        # Image may need to be offline to be repaired
                        $cannotPerform = @(
                            "c.o.u.l.d...n.o.t...p.e.r.f.o.r.m...t.h.e...r.e.q.u.e.s.t.e.d...o.p.e.r.a.t.i.o.n."
                        )

                        $restartRequired = @(
                            "T.h.e.r.e...i.s...a...s.y.s.t.e.m...r.e.p.a.i.r...p.e.n.d.i.n.g...w.h.i.c.h...r.e.q.u.i.r.e.s...r.e.b.o.o.t...t.o...c.o.m.p.l.e.t.e."
                        )

                        $adminRequired = @(
                            "Y.o.u...m.u.s.t...b.e...a.n...a.d.m.i.n.i.s.t.r.a.t.o.r"
                        )

                        $SFCResponses = @(
                            @{Name = "Clean" ; Response = $clean ; Bool = $False },
                            @{Name = "Corrupted" ; Response = $corrupted ; Bool = $False },
                            @{Name = "CannotPerform" ; Response = $cannotPerform ; Bool = $False },
                            @{Name = "RestartRequired" ; Response = $restartRequired ; Bool = $False },
                            @{Name = "AdminRequired" ; Response = $adminRequired ; Bool = $False },
                            @{Name = "ServiceRequired" ; Response = $serviceRequired ; Bool = $False }
                        )

                        Write-Verbose -Message "Starting SFC with '/scannow' switch..."

                        $imageSFC = C:\WINDOWS\system32\sfc.exe /scannow

                        Write-Verbose -Message "Completed SFC scan"

                    }
                    catch {
                        $PSCmdlet.ThrowTerminatingError($PSitem)
                    }
                    
                }
                
                process {
                
                    try {
                        Write-Verbose -Message "Parsing information..."
                        $SFC = foreach ($SFCResponse in $SFCResponses) {
                            $exist = $imageSFC | Select-String -Pattern $SFCResponse.Response
                            [PSCustomObject]@{
                                State       = $SFCResponse.Name
                                Bool        = [bool]($null -ne $exist)
                                Description = if ($null -ne $exist) { $exist -replace "\s{1}\b", "" } else { $null }
                            }
                        }

                        if (!($SFC | Where-Object {$PSItem.bool -eq $true})) {
                            Write-Error -Message "Something weird happened with PowerShell and was unable to parse SFC output"
                        }
                        
                        $SFC
                
                    }
                    catch {
                        $PSCmdlet.ThrowTerminatingError($PSitem)
                    }
                }
                
                end {

                }
            }

            Function Test-IsFileLocked {
                [cmdletbinding()]
                Param (
                    [parameter(Mandatory, 
                        ValueFromPipeline, 
                        ValueFromPipelineByPropertyName)]
                    [Alias('FullName', 'PSPath')]
                    [string[]]$Path
                )
                Process {
                    ForEach ($Item in $Path) {
                        # Ensure this is a full path
                        $Item = Convert-Path $Item
                        # Verify that this is a file and not a directory
                        If ([System.IO.File]::Exists($Item)) {
                            Try {
                                $FileStream = [System.IO.File]::Open($Item, 'Open', 'Write')
                                $FileStream.Close()
                                $FileStream.Dispose()
                                $IsLocked = $False
                                return $False
                            }
                            Catch [System.UnauthorizedAccessException] {
                                $IsLocked = 'AccessDenied'
                            }
                            Catch {
                                $IsLocked = $True
                                return $True
                            }
                            [pscustomobject]@{
                                File     = $Item
                                IsLocked = $IsLocked
                            }
                        }
                    }
                }
            }
                    
            function Test-Internet {
                <#
                .SYNOPSIS
                    A simple function to grab the success rate of testing a destination's connection
                .DESCRIPTION
                    A simple function to grab the success rate of testing a destination's connection and output as a consumable object.
                .PARAMETER Destination
                    Destination you wish to test
                .PARAMETER Count
                    Amount of times you want to test each destination
                .INPUTS
                    Description of objects that can be piped to the script.
                .OUTPUTS
                    Description of objects that are output by the script.
                .EXAMPLE
                    Test-Internet -Destination "www.google.com"
                .LINK
                    Links to further documentation.
                .NOTES
                    Detail on what the script does, if this is needed.
                #>
                [CmdletBinding()]
                param(
                    [parameter(Mandatory)]
                    [string[]]$Destination,
            
                    [parameter()]
                    [int]$Count = 5
                )
                
                begin {
                    $testConnectionParams = @{
                        Count       = $Count 
                        ErrorAction = 'SilentlyContinue'
                    }
                }
                process {
                    foreach ($dest in $Destination) {
                        $testConnectionParams.ComputerName = $dest
                        $successRate = Test-Connection @testConnectionParams
                        [PSCustomObject]@{
                            Destination = $dest
                            SuccessRate = [int]$("{0:N2}" -f (($successRate.count / $Count) * 100))
                            Count       = $Count
                        }    
                    }
                }
            }        

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
            
            function Wait-Condition {
                [CmdletBinding()]
                param (
                    [Parameter(Mandatory)]
                    [ValidateNotNullOrEmpty()]
                    [scriptblock]$Condition,
            
                    [Parameter()]
                    [ValidateNotNullOrEmpty()]
                    [int]$CheckEvery = 30,
            
                    [Parameter()]
                    [ValidateNotNullOrEmpty()]
                    [int]$Timeout = 600
                )
            
                $ErrorActionPreference = 'Stop'
                
            
                try {
                    # Start the timer
                    $timer = [Diagnostics.Stopwatch]::StartNew()
            
                    # Keep in the loop while the item is false
                    Write-Verbose -Message "Waiting for condition..."
                    while (-not (& $Condition)) {
                        $logger.Informational("Waiting for condition... $Condition")
                        Write-Verbose -Message "Waiting for condition..."
                        # If the timer has waited greater than or equal to the timeout, throw an exception exiting the loop
                        if ($timer.Elapsed.TotalSeconds -ge $Timeout) {
                            $logger.error("Timeout exceeded. Giving up... $Condition")
                            throw "Timeout exceeded. Giving up..."
                        }
                        # Stop the loop every $CheckEvery seconds
                        Start-Sleep -Seconds $CheckEvery
                    }
                }
                catch {
                    $PSCmdlet.ThrowTerminatingError($_)
                }
                finally {
                    $timer.Stop()
                }
                
            }

        }
        catch {
            $PSCmdlet.ThrowTerminatingError($PSitem)
        }

    }
    
    process {

        # Test for the locked CBS log file
        if (Test-IsFileLocked -Path $cbsPath) {
            Wait-Condition -condition { 
                Write-Verbose -Message "File $cbsPath is locked currently"
                $logger.Informational("File $cbsPath is locked currently")

                Try {
                    Write-Verbose -Message "Stopping TrustedInstaller Service..."
                    $logger.Warning("Trying to stop TrustedInstaller Service")
                    Stop-Service -Name "TrustedInstaller" -Force -ErrorAction Stop

                    (Get-Service -Name "TrustedInstaller").WaitForStatus('Stopped', '00:00:15')
                    $logger.Informational("Stopped TrustedInstaller Service")
                }
                Catch {
                    $logger.error("$_.message Unable to stop the TrustedInstaller Service")
                    Write-Error "$_.message Unable to stop the TrustedInstaller Service"
                }
            } -Timeout 300 -ErrorAction Stop
        }
        
        # Test CBS log path and see if system was scanned before or not
        if (!(Test-Path -Path "$cbsPath")) {
            Write-Verbose -Message "Creating CBS Logs..."
            $logger.Informational("$cbsPath has not been created yet. No scans have completed or have been run.")
        }
        else {
            # Remove Logs older than five minutes and create new
            Write-Verbose -Message "CBS Logs are older than 5 minutes, Recreating..."
            $logger.Informational("CBS Logs are older than 5 minutes, Recreating...")

            $logger.Warning("Removing $cbsPath")
            Get-ChildItem -Path "$cbsPath" | Where-Object { $_.CreationTime -lt (Get-Date).AddMinutes($CBSLifeSpan) } | Remove-Item
            
            Write-Output "Please be patient as this takes about 5-10 minutes..."
            Write-Verbose -Message "Recreating CBS Logs..."
        }
        
        Write-Verbose -Message "Getting SFC Results..."
        $SFCResponses = Get-SFCResult
        ($SFCResponses | Where-Object {$PSItem.bool -eq $true})

        Wait-Condition -condition { Resolve-ReagentC }
        
        if ((Get-ComponentStoreStatus).CleanupRecommended -eq $true) {
            Wait-Condition -Condition { Optimize-ComponentStore } -Timeout 900
        }
        
        Write-Verbose -Message "Running Online Image Health Check"
        $logger.Informational("Running Online Image Health Check")
        $imageCheckHealth = Repair-WindowsImage -Online -CheckHealth @logLevel

        if ($imageCheckHealth.ImageHealthState -ne "Healthy") {
            Write-Warning -Message "Image Health Check Indicates Corruption"
            $logger.Warning("Image Health Check Indicates Corruption...")

            Write-Verbose -Message "Running Online Image Health Scan"
            $logger.Informational("Running Online Image Health Scan")

            $imageScanHealth = Repair-WindowsImage -Online -ScanHealth @logLevel

            if ($imageScanHealth.ImageHealthState -ne "Healthy") {

                If ((Test-Internet -Destination "www.google.com").SuccessRate -ge $AcceptableRate) {
                    try {
                        # Restore health fixes component store corruption
                        Write-Verbose -Message "Running Online Image Health Restore..."
                        $logger.Informational("Running Online Image Health Restore...")

                        $imageRestoreHealth = Repair-WindowsImage -Online -RestoreHealth @logLevel
                    }
                    catch {
                        $UseSource = $true
                        Write-Error -Message "Unable to finish Online Restore health. Use a local image as a source"
                        $logger.Error("$PSItem")
                    }
                }
                else {
                    $UseSource = $true
                    Write-Warning "Connection to windows update is spotty. Repair will proceed from a local image as a source."
                    $logger.Warning("Connection to windows update is spotty. Repair will proceed from a local image as a source.")
                }

            }
            else {
                Write-Verbose -Message "Getting SFC Results..."
                $SFCResponses = Get-SFCResult
                $SFCResponses | Where-Object {$PSItem.bool -eq $true}
            }

        }

        if (($UseSource) -or (($SFCResponses | Where-Object {($PSItem.State -match "Clean" -and $PSItem.bool -eq $false)}))) {

            Write-Verbose -Message "Initializing Image Source Mounting"
            $logger.Informational("Initializing Image Source Mounting")

            foreach ($imageSource in $Path) {

                if (!([string]::IsNullOrWhiteSpace($imageSource))) {

                    if ($imageSource -like "*ISO" ) {
                        # Copy iso
                        $logger.Informational("Downloading $imageSource...")
                        Start-BitsTransfer -Source $imageSource -Destination "$home\downloads\Windows.iso" -Description "download install ISO file"

                        # Find the Drive letter to mounted image
                        $logger.Informational("Mounting Image Source...")
                        $mountedDrive = Mount-DiskImage -ImagePath $imageSource -PassThru | Get-DiskImage | Get-Volume
                        
                        # Find full path to ESD or WIM
                        $logger.Informational("Resolving full path to Image Source...")
                        $mountedImageSource = Get-ChildItem -Path "$($mountedDrive.DriveLetter):\" -Recurse | 
                        Where-Object { ($_.Name -like "Install.esd" -or $_.name -like "Install.Wim") } |
                        Select-Object -ExpandProperty FullName

                        # Find the correct index to the current system
                        $logger.Informational("Indexing Source...")
                        $windowsIndex = Get-WindowsImage -ImagePath "$mountedImageSource" | 
                        Where-Object { ($_.imageName -match "$winProductName" -and $_.imageName -notlike "$winProductName N" ) } | 
                        Sort-Object imageName | Select-Object -First 1

                        Write-Verbose -Message "Using $mountedImageSource as source to repair component store corruption"
                        try {
                            $logger.Informational("Starting Windows Repair...")

                            $repairParams.Source = "$($mountedImageSource):$($windowsIndex.ImageIndex)"
                            Repair-WindowsImage @repairParams @logLevel
                        }
                        catch {
                            $logger.Error("$PSItem")
                            $PSItem
                        }

                        Dismount-DiskImage -ImagePath $imageSource
                    }
                    else {
                        Write-Verbose -Message "Downloading $imageSource..."
                        $logger.Informational("Downloading $imageSource...")
                        Start-BitsTransfer -Source $imageSource -Destination "$home\downloads\install.wim" -Description "download install wim file"

                        Write-Verbose -Message "Resolving full path to Image Source..."
                        $logger.Informational("Resolving full path to Image Source...")
                        $copiedSource = Get-ChildItem -Path "$home\downloads\install.wim"

                        Write-Verbose -Message "Indexing Source..."
                        $logger.Informational("Indexing Source...")
                        $windowsIndex = Get-WindowsImage -ImagePath $copiedSource | 
                        Where-Object { ($_.imageName -match "$winProductName" -and $_.imageName -notlike "$winProductName N" ) } |
                        Sort-Object imageName | Select-Object -First 1

                        try {
                            Write-Verbose -Message "Using $imageSource as source to repair component store corruption"
                            $logger.Informational("Starting Windows Repair...")

                            $repairParams.Source = "$($imageSource):$($windowsIndex.ImageIndex)"
                            Repair-WindowsImage @repairParams @logLevel

                        }
                        catch {
                            $logger.Error("$PSItem")
                            $PSItem
                        }

                    }

                }
                else {
                    $logger.Warning("Image source was either null or does not exist")
                    Write-Warning -Message "Image source was either null or does not exist"
                }

                $imageCheckHealth = Repair-WindowsImage -Online -CheckHealth @logLevel
                if (($imageCheckHealth.ImageHealthState -ne "healthy") -or (($SFCResponses | Where-Object {($PSItem.State -match "Clean" -and $PSItem.bool -eq $false)}))) {
                    $logger.Notice("Trying next Image Source...")
                }
                else {
                    $logger.Informational("Image report came back as healthy. Breaking Loop.")
                    break
                }

            }

            Write-Verbose -Message "Getting SFC Results..."
            $SFCResponses = Get-SFCResult
            $SFCResponses | Where-Object {$PSItem.bool -eq $true}

        }
        else {
            $logger.Informational("Online Image Health Check Has No Indication of Corruption")
            Write-Host "Online Image Health Check Has No Indication of Corruption" -ForegroundColor Green
        }
    }
    end {

        if ($imageCheckHealth.ImageHealthState -eq "Healthy"){
            $logger.Informational("Image is $($imageCheckHealth.ImageHealthState)")
        } else {
            $logger.Alert("Image is $($imageCheckHealth.ImageHealthState)")
        }

        $imageCheckHealth
        
        $logger.Notice("Finished $($MyInvocation.MyCommand) script")

        $scriptTimer.stop()
        $logger.Informational("Script Runtime:$($scriptTimer.Elapsed.ToString())")
        Start-Sleep -Seconds 7
    }
}