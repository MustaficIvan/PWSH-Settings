# Module
import-Module 'Terminal-Icons'
oh-my-posh init pwsh --config "C:\Users\Ivan\scoop\apps\oh-my-posh\current\themes\ivan.omp.json" | Invoke-Expression
Import-Module PSReadLine
Set-PSReadLineOption -PredictionSource History
Set-PSReadLineOption -PredictionViewStyle ListView

function Copy-Path
{ $pwd.Path | clip 
}
function Get-ComPort
{ Get-CimInstance -ClassName Win32_PnPEntity | where {$_.Name -like "*(COM*)*"} | Sort Name | Format-Table Name 
}
function Get-Info
{ Get-Content $PROFILE.CurrentUserCurrentHost 
}
function Stop-Task
{ param([string]$p1) Stop-Process -Name $p1 
}
function Get-AllChildren
{
  Get-ChildItem -hidden; Write-Host "`n ---------------------------HIDDEN----------------------------- `n";ls
}

# Use the -> btop command here and ther 
# To use ps2exe it has to be in Windows Powershell
# Alias
Set-Alias -Name grep -Value Select-String
Set-Alias -Name ll -Value ls
Set-Alias -Name la -Value Get-AllChildren
Set-Alias -Name stop -Value Stop-Task 
Set-Alias -Name ci -value Copy-Item
New-Alias -Name path -value Copy-Path
Set-Alias -Name extract -value Expand-Archive
Set-Alias -Name com -value Get-ComPort
Set-Alias -Name task -value Get-Process
Set-Alias -Name info -value Get-Info

Set-Alias -Name py -value python
Set-Alias -Name p -value python
Set-Alias -Name extract -value Expand-Archive

Set-Alias -Name nivm -Value nvim
Set-Alias -Name vi -value nvim
Set-Alias -Name vim -value nvim
