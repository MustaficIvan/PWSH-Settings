Function Set-ModuleBash {
    If (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' -Name 'AllowDevelopmentWithoutDevLicense' -Value 1
        Enable-WindowsOptionalFeature -Online -FeatureName 'Microsoft-Windows-Subsystem-Linux'
    } Else {
        Start-Process -FilePath PowerShell -Verb RunAs '-Command Set-ModuleBash'
    }
}

Function Invoke-BashCommand {
    Bash -c "$($MyInvocation.InvocationName) $Args"
}

Function Add-BashCommand {
    Param(
        [Parameter(
            Mandatory = $True
        )]
        [String] $Command
    )
    Set-Alias -Name $Command -Value Invoke-BashCommand -Scope Global -ErrorAction Stop
    If (-Not (Test-Path -PathType Leaf -Path $Profile)) {
        New-Item -ItemType File -Path $Profile
    }
    $Content = "Set-Alias -Name $Command -Value Invoke-BashCommand"
    If (-Not (Get-Content -Path $Profile | Select-String -SimpleMatch $Content)) {
        Add-Content -Path $Profile -Value $Content
    }
}

Function Remove-BashCommand {
    Param(
        [Parameter(
            Mandatory = $True
        )]
        [String] $Command
    )
    Remove-Item Alias:$Command
    If (Test-Path -PathType Leaf -Path $Profile) {
        $Content = Get-Content -Path $Profile | Select-String -NotMatch -Pattern "Set-Alias -Name $Command -Value Invoke-BashCommand"
        Set-Content -Path $Profile -Value $Content
    }
}

Function Get-BashCommand {
    Param(
        [String] $Command
    )
    If ($Command) {
        If (Get-Content -Path $Profile | Select-String -Pattern "Set-Alias -Name $Command -Value Invoke-BashCommand") {
            Write-Output $Command
        }
    } Else {
        $MatchesCommands = Get-Content -Path $Profile | Select-String -Pattern "Set-Alias -Name (\w+) -Value Invoke-BashCommand"
        ForEach ($Match in $MatchesCommands.Matches) {
            Write-Output $Match.Groups[1].Value
        }
    }
}