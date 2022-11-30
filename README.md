# Introduction
This is a set of scripts that can help with windows image repair. When running into corrupted files in windows you may need repair them and you need to do it in a certain order

# Requirements and Dependencies
* [PowerShell 5.1](https://www.microsoft.com/en-us/download/details.aspx?id=54616) or later
* https://github.com/kewlx/PSLogger/blob/main/Logging.ps1
    * Optimize-ComponentStore, Repair-Image, and Resolve-ReAgentC rely on PSLogger to be accessible or you can comment out anything $logger
    * You will have to change `."\\server\path\here\Logging.ps1"` to point to the accessible path if you want to use it.

## Usage

1. You will need to make sure that the `Trusted Installer service`, or called `Windows Modules Installer`, is in at least manual mode and started
    * If you do not then the next step will warn you that a service is not running
2. Run `Get-SFCResult` on the machine
    * This will run the SFC /Scannow command and output an object for you indicating the status.
    * If the status says that there are corrupted files and it was unable to fix them then continue on to the next step.
3. Run `Get-CBSResult` on the machine
    * This will output the specific files that were corrupted and fixed or still corrupted. This parses the CBS log for you.
    * Continue on to the next steps if there are corrupted files.
4. Run `Repair-WindowsImage -Online -ScanHealth`
   * The ScanHealth parameter scans the image for component store corruption. This operation will take several minutes.
5. Run `Repair-WindowsImage -Online -RestoreHealth`
   * The RestoreHealth parameter scans the image for component store corruption, and then performs repair operations automatically. This operation will take several minutes.
6. Rerun steps 2 and 3

You can also try using the more in-depth version by running `Repair-Image` - Remember to review dependencies before running. Otherwise you will get errors about logging.
1. You will need a copy of that systems iso and the correct version. Examples below.
    * Win 10 1909 needs a Win 10 1909 iso
    * Windows Server 2012 R2 needs the Windows Server 2012 R2 iso, be aware of datacenter versus standard versions
2. Run Repair-Image on the machine like this `Repair-Image -Path "Path\to\iso\here\isoNameHere.iso"`
    * This will check the system and try to repair it from local files, then online files provided by microsoft and if it can not via those two methods, then it will use the ISO provided to repair the system. It will let you know if it succeeded or not.

Run the following command to get help on a specific Command

```Powershell
Get-Help <NameOfCommand>

Example: Get-Help Get-SFCResult -Full
```
