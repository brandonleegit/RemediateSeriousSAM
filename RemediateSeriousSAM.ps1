#PowerShell script to check for the SeriousSAM/HiveNightmare vulnerability and remediate 
#Use at your own risk! 
#Author: Brandon Lee - Virtualizationhowto.com 

$placeholder = "check.txt" 
$log = "SeriousSAM.log" 
try { 
         
    Write-Host "Checking for SeriousSAM and HiveNightmare vulnerability" -ForegroundColor Yellow 
    Get-Acl $env:windir\system32\config\SAM | fl | out-file $placeholder 
    $check = Get-Content $placeholder | Where-Object { $_.Contains("BUILTIN\Users") } 
         
    if ($check -ne $null) { 
        try { 
             
            Write-Warning "Your Machine is Vulnerable to the SeriousSAM and HiveNightmare vulnerability - Apply permissions changes and delete VSS copies?" -WarningAction Inquire 
            icacls c:\windows\system32\config\*.* /inheritance:e > $log 
            vssadmin delete shadows /All /Quiet >> $log 
            Remove-Item $placeholder 
            Write-Host "Your computer is now remediated" -ForegroundColor Green 
        } 
        catch { 
            Write-Host "You chose not to remediate your host" -ForegroundColor Red 
        } 
    }     
    else { 
        Remove-Item $placeholder 
        Write-Host "Your Machine is not vulnerable to the SeriousSAM or HiveNightmare" -ForegroundColor Green 
    } 
} 
         
catch { 
    Write-Host "Error running the script" -ForegroundColor Red 
}