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