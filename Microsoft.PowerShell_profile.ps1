# Module
import-Module 'Terminal-Icons'
oh-my-posh init pwsh --config "$env:POSH_THEMES_PATH/newer.omp.json" | Invoke-Expression
Import-Module PSReadLine
Set-PSReadLineOption -PredictionSource History
Set-PSReadLineOption -PredictionViewStyle ListView

function Copy-Path { $pwd.Path | clip }

# Alias
Set-Alias -Name grep -Value findstr
Set-Alias -Name ll -Value ls
Set-Alias -Name stop -Value Stop-Process
Set-Alias -Name ci -value Copy-Item
New-Alias -Name path -value Copy-Path

Set-Alias -Name py -value python
Set-Alias -Name p -value python
Set-Alias -Name extract -value Expand-Archive

Set-Alias -Name nivm -Value nvim
Set-Alias -Name vi -value nvim
Set-Alias -Name vim -value nvim
