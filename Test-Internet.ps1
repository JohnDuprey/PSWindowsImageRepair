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
