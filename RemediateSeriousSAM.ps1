#PowerShell script to check for the SeriousSAM/HiveNightmare vulnerability and remediate 
#Use at your own risk! 
#Author: Brandon Lee - Virtualizationhowto.com 

#   Updated: Vincent Zhen - vincent.zhen@mongodb.com

Param (
    [switch]$NoPrompt,
    [string]$LogFile = "SeriousSAM.log"
)

function Rcv-Output {
    Param (
        [string]$ForegroundColor = "White"
        )
    process { Write-Host $_ -ForegroundColor $ForegroundColor }
}

Start-Transcript -Path $LogFile
Write-Output ""
try { 
         
    Write-Output "[+] Checking for SeriousSAM and HiveNightmare vulnerability" | Rcv-Output -ForegroundColor Yellow
    $check = [string]::join(" - ",(((Get-Acl $env:windir\System32\config\SAM).Access | ForEach-Object { '{0}|{1}|{2}' -f $_.IdentityReference,$_.AccessControlType,$_.FileSystemRights }).Split("`n"))) | Where-Object { $_.Contains("BUILTIN\Users") } 
         
    if ($check -ne $null) { 
        try { 
            if ($NoPrompt) {
                Write-Output "[!] Your Machine is Vulnerable to the SeriousSAM and HiveNightmare vulnerability" | Rcv-Output -ForegroundColor Red
            }
            else {
                Write-Warning "[!] Your Machine is Vulnerable to the SeriousSAM and HiveNightmare vulnerability - Apply permissions changes and delete VSS copies?" -WarningAction Inquire 
            }
            icacls c:\windows\system32\config\*.* /inheritance:e
            vssadmin delete shadows /All /Quiet
            Write-Output "[+] Your computer is now remediated" | Rcv-Output -ForegroundColor Green
        } 
        catch { 
            Write-Output "[+] You chose not to remediate your host" -ForegroundColor Red 
        } 
    }     
    else { 
        Write-Output "[+] Your Machine is not vulnerable to the SeriousSAM or HiveNightmare" | Rcv-Output -ForegroundColor Green
    } 
} 
         
catch { 
    $ErrMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    Write-Output "[!] Error running the script: ($FailedItem) $ErrMessage" | Rcv-Output -ForegroundColor Red
}

Write-Output ""
Stop-Transcript
