# Promt
Import-Module oh-my-posh
Import-Module Terminal-Icons
Set-PoshPrompt -Theme '~/.mytheme.omp.json'
Import-Module PSReadLine
Set-PSReadLineOption -PredictionSource History
Set-PSReadLineOption -PredictionViewStyle ListView

# Alias
Set-Alias -Name grep -Value findstr
Set-Alias -Name ll -Value ls
Set-Alias -Name nivm -Value nvim
Set-Alias -Name wh -Value Write-Host
Set-Alias -Name stop -Value Stop-Process
Set-Alias -Name python -value py
Set-Alias -Name p -value 'python3.10'
Set-Alias -Name 'p3.9' -Value 'C:\Users\ivanm\AppData\Local\Programs\Python\Python39\python.exe'
