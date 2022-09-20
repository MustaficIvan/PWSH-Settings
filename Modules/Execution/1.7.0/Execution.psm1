function Set-ScriptArgs {
    [CmdletBinding()]
    param(
        [Parameter()]
        [System.Collections.Generic.Dictionary`2[System.String, System.Object]]
        $BoundParameters,

        [Parameter()]
        [System.Collections.Generic.List`1[System.Object]]
        $UnboundArguments
    )

    $Global:PSCommandPath = $MyInvocation.PSCommandPath
    Log trace "Global:PSCommandPath: '$Global:PSCommandPath'"

    $argumentList = [System.Collections.ArrayList]@()

    $parameters = (Get-Command $Global:PSCommandPath).Parameters

    Log trace 'Parse bound parameters...'
    foreach ($key in $BoundParameters.Keys) {
        $type = $parameters.Values | Where-Object { $_.Name -eq $key } | Select-Object -ExpandProperty ParameterType

        Log trace "Parametertype: '$($type.FullName)'"
        switch ($type) {
            ([System.Management.Automation.SwitchParameter]) { $value = '$true' }

            ([System.Boolean]) {
                try {
                    $boolValue = [System.Convert]::ToBoolean($BoundParameters[$key])
                } catch {
                    $boolValue = $false
                }

                $value = if ($boolValue) { '$true' } else { '$false' }
            }

            default { $value = $BoundParameters[$key] }
        }

        Log trace "-$key`:$value"
        $argumentList.Add("-$key`:$value") > $null
    }
    Log trace 'Parse bound parameters... Done.'

    Log trace 'Parse unbound arguments...'
    foreach ($arg in $UnboundArguments) {
        Log trace "$arg"
        $argumentList.Add($arg) > $null
    }
    Log trace 'Parse unbound arguments... Done.'

    $Global:ScriptArgs = $argumentList
    Log trace "Global:ScriptArgs: '$Global:ScriptArgs'"
}

function Invoke-SelfElevation() {
    # Self-elevate the script if required
    if ($PSVersionTable.Platform -eq 'unix') {
        if ((id -u) -ne 0) {
            Log trace 'Try self elevation on Unix platform...'

            $executionInfo = Get-ExecutionInfo
            & sudo $executionInfo.Executable @($executionInfo.ArgumentList)
            exit 0
        }
    } else {
        if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'administrator')) {
            if ([int] (Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
                Log trace 'Try self elevation on Windows platform...'

                $executionInfo = Get-ExecutionInfo

                $hashAndFile = Get-HashAndFile -Executable $executionInfo.Executable -Arguments $executionInfo.Arguments
                Log trace "Write mutex file with hash to '$($hashAndFile.File)'"
                New-Item -Path $hashAndFile.File -ItemType File -Force > $null

                Start-Process -FilePath $executionInfo.Executable -ArgumentList $executionInfo.Arguments -WorkingDirectory $PSScriptRoot -Verb runas
                exit 0
            }
        }
    }
}

function Exit-WithAndWaitOnExplorer([int] $ExitCode) {
    if ($PSVersionTable.Platform -ne 'unix') {
        $parentProcessId = Get-CimInstance Win32_Process -Filter "ProcessId = $PID" | Select-Object -ExpandProperty ParentProcessId
        if ($parentProcessId) {
            $parentParentProcessId = Get-CimInstance Win32_Process -Filter "ProcessId = $parentProcessId" | Select-Object -ExpandProperty ParentProcessId
            if ($parentParentProcessId) {
                $parentParentProcessName = Get-CimInstance Win32_Process -Filter "ProcessId = $parentParentProcessId" | Select-Object -ExpandProperty Name
            }
        }

        $executionInfo = Get-ExecutionInfo

        $hashAndFile = Get-HashAndFile -Executable $executionInfo.Executable -Arguments $executionInfo.Arguments
        Log trace "Check if mutex file exists '$($hashAndFile.FileName)'..."
        $mutexFileExists = Test-Path -Path $hashAndFile.File
        if ($mutexFileExists) {
            Log trace "Mutex file exists '$($hashAndFile.File)'"
            Remove-Item -Path $hashAndFile.File -Force > $null
        }

        if (($parentParentProcessId -and $parentParentProcessName -eq 'explorer.exe') -or $mutexFileExists) {
            Log info 'Press any key to continue . . . '
            $HOST.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') > $null
            $HOST.UI.RawUI.FlushInputBuffer()
        }

        exit $ExitCode
    }

    exit $ExitCode
}

function Get-ExecutionInfo() {
    $executable = Get-Process -Id $PID | Select-Object -ExpandProperty MainModule | Select-Object -ExpandProperty FileName
    $argumentList = @('-NoProfile', '-ExecutionPolicy', 'Unrestricted', '-Command', "`"& `"$Global:PSCommandPath`" $Global:ScriptArgs`"")
    $arguments = "$argumentList"
    Log trace "executable:   $executable"
    Log trace "argumentList: $argumentList"
    Log trace "arguments:    $arguments"

    $executionInfo = [pscustomobject][ordered]@{
        'Executable'   = $executable
        'ArgumentList' = $argumentList
        'Arguments'    = $arguments
    }
    return $executionInfo
}

function Get-HashAndFile([string] $Executable, [string] $Arguments) {
    $value = "$Executable $Arguments".ToLowerInvariant()
    $fileName = Get-Checksum -Value $value
    $file = (Join-Path $env:TEMP $fileName)

    $object = [pscustomobject][ordered]@{
        'FileName' = $fileName
        'File'     = $file
    }
    return $object
}

function Invoke-Process {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Command,

        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]] $CommandArgs
    )

    $commandString = $Command
    if ($commandArgs) {
        $commandString += " $commandArgs"
    }

    Write-Host "Execute: '$commandString'" -ForegroundColor DarkYellow

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $command
    $startInfo.Arguments = $commandArgs
    $startInfo.UseShellExecute = $false
    $startInfo.WorkingDirectory = Get-Location

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    $process.Start() > $null

    $finished = $false
    try {
        while (-not $process.WaitForExit(100)) {
            # Non-blocking loop done to allow ctr-c interrupts
        }

        $finished = $true
        return $global:LASTEXITCODE = $process.ExitCode
    } finally {
        # If we didn't finish then an error occured or the user hit ctrl-c. Either way kill the process
        if (-not $finished) {
            $process.Kill()
        }
    }
}

function Start-NativeExecution() {
    $backupEap = $Script:ErrorActionPreference
    $Script:ErrorActionPreference = 'Continue'

    try {
        if ($args.Length -lt 1) {
            Log warning 'No arguments specified'
            return
        }

        Log trace "Execute: '$args'"

        $command = $args[0] | Get-QuotedPath
        $arguments = $args | Select-Object -Skip 1 | Get-QuotedPath

        Log trace "Command:   '$command'"
        if ($arguments -and $arguments.Length -gt 0) {
            Log trace "Arguments: '$arguments'"
        }

        $wrapperScriptBlock = [ScriptBlock]::Create("& $command $arguments")

        $calledFromPrompt = Test-CalledFromPrompt
        if ($calledFromPrompt) {
            $wrapperScriptBlock = [ScriptBlock]::Create("& $command $arguments")
        } else {
            $wrapperScriptBlock = [ScriptBlock]::Create("& $command $arguments 2>&1")
        }

        Log trace "WrapperScriptBlock: '$wrapperScriptBlock'"

        $messages = & $wrapperScriptBlock

        # NOTE: If $wrapperScriptBlock's command doesn't have a native invocation,
        # $LASTEXITCODE will point to the obsolete value
        Log trace "LASTEXITCODE: $LASTEXITCODE"
        Log trace "`$?: $?"

        # Need to check both of these cases for errors as they represent different items
        # - $?: Did the powershell script block throw an error
        # - $LASTEXITCODE: Did a windows command executed by the script block end in error
        if ((-not $?) -or ($LASTEXITCODE -and $LASTEXITCODE -ne 0)) {
            if ($Error -ne $null) {
                Log error $Error[0]
            }

            Log error "Execution of '$args' failed with exit code $LASTEXITCODE."
            $logLevel = 'error'
        } else {
            $logLevel = 'info'
        }

        if ($calledFromPrompt -and (Test-Path Variable:\messages)) {
            if ($messages -is [System.Object[]]) {
                foreach ($message in $messages) {
                    if ($message.GetType() -eq [System.Management.Automation.ErrorRecord]) {
                        $lines = $message.Exception.Message.Split("`r`n", [System.StringSplitOptions]::RemoveEmptyEntries)
                    } elseif ($message.GetType() -eq [string]) {
                        $lines = $message.Split("`r`n", [System.StringSplitOptions]::RemoveEmptyEntries)
                    }

                    if (Test-Path Variable:\lines) {
                        $lines | Log $logLevel
                    }
                }
            }

            if ($messages -is [string]) {
                $messages.Split("`r`n", [System.StringSplitOptions]::RemoveEmptyEntries) | Log $logLevel
            }
        }
    } catch {
        if ($_.Exception -and $_.Exception.Message) {
            $_.Exception.Message.Split("`r`n", [System.StringSplitOptions]::RemoveEmptyEntries) | Log error
        }
    } finally {
        if (-not (Test-Path Variable:\messages)) {
            $messages = $null
        }

        $Script:ErrorActionPreference = $backupEap
    }

    return $messages
}

function Get-QuotedPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string] $Path
    )

    process {
        Log trace "Path: $Path"

        if ($Path -match '\s') {
            return "`"$Path`""
        } else {
            return $Path
        }
    }
}

function Test-CalledFromPrompt() {
    $command = (Get-PSCallStack)[-2].Command
    Log trace "PromptCommand: $command"

    return ($command -eq 'prompt')
}

function Clear-TempDirectories {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]] $AdditionalPaths,

        [Parameter()]
        [switch] $TryRun
    )

    $tempDirName = 'temp'

    $dirs = [System.Collections.ArrayList]@()

    Add-ItemWhenExists -Item (Join-Path $env:ProgramFiles $tempDirName) -List $dirs
    Add-ItemWhenExists -Item (Join-Path ${env:ProgramFiles(x86)} $tempDirName) -List $dirs
    Add-ItemWhenExists -Item (Join-Path $env:windir $tempDirName) -List $dirs

    $userDirs = Get-ChildItem 'C:/Users' -Directory -Force
    foreach ($userDir in $userDirs) {
        Add-ItemWhenExists -Item (Join-Path $userDir.FullName "AppData/Local/$tempDirName") -List $dirs
        Add-ItemWhenExists -Item (Join-Path $userDir.FullName "AppData/LocalLow/$tempDirName") -List $dirs
        Add-ItemWhenExists -Item (Join-Path $userDir.FullName "AppData/Roaming/$tempDirName") -List $dirs
    }

    if ($AdditionalPaths) {
        $AdditionalPaths | Add-ItemWhenExists -List $dirs
    }

    for ($i = 0; $i -lt $dirs.Count; $i++) {
        $items = $dirs[$i] | Get-ChildItem -Recurse -Force -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName | Sort-Object -Descending -Property Length
        $total = $items | Measure-Object | Select-Object -ExpandProperty Count
        Log trace "Found '$total' items in '$($dirs[$i])' to remove"

        Write-Progress -Id 1 -Activity 'Clear TEMP directories' -Status "Step $($($i + 1).ToString().PadLeft($dirs.Count.ToString().Length)) of $($dirs.Count)" -CurrentOperation "Remove all items in '$($dirs[$i])'" -PercentComplete (($i + 1) / $dirs.Count * 100)

        for ($ii = 0; $ii -lt $items.Count; $ii++) {
            Write-Progress -Id 2 -ParentId 1 -Activity 'Processing items' -Status "Item $($($ii + 1).ToString().PadLeft($items.Count.ToString().Length)) of $($items.Count)" -CurrentOperation "Remove item '$($items[$ii])'" -PercentComplete (($ii + 1) / $items.Count * 100)
            if (-not $TryRun) {
                Remove-ItemSafe -Path $items[$ii] -Retries 16 -Milliseconds 10
            } else {
                Start-Sleep -Milliseconds 1
            }
        }
    }
}

function Add-ItemWhenExists {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [string] $Item,

        [Parameter()]
        [System.Collections.ArrayList] $List
    )

    process {
        if ($Item -and (Test-Path $Item)) {
            $List.Add($Item) > $null
        }
    }
}

function Remove-ItemSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string] $Path,

        [Parameter()]
        [int] $Retries = 255,

        [Parameter()]
        [int] $Milliseconds = 75
    )

    process {
        Log trace "Remove item safe '$Path'..."

        while ($path -and (Test-Path -Path $Path -ErrorAction SilentlyContinue) -and ($Retries -gt 0)) {
            try {
                if ((Test-Path -Path $Path -PathType Container) -and ((Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count) -gt 0)) {
                    Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue > $null
                } else {
                    Remove-Item -Path $path -Force -ErrorAction SilentlyContinue > $null
                }
            } catch {
                Start-Sleep -Milliseconds $Milliseconds
            } finally {
                --$Retries
            }
        }
    }
}

function Invoke-WhenFileChanged {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [string] $File,

        [Parameter(Mandatory )]
        [string] $Action,

        [Parameter()]
        [int] $PoolingIntervalInMS = 100
    )

    Process {
        $global:FileChanged = $false
        $executeCounter = 0

        $File = Resolve-Path $File

        $filePath = Split-Path $File -Parent
        $fileName = Split-Path $File -Leaf
        $scriptBlock = [scriptblock]::Create($Action)

        $watcher = New-Object IO.FileSystemWatcher $filePath, $fileName -Property @{
            IncludeSubdirectories = $false
            EnableRaisingEvents   = $true
        }

        Log info "::: [$(Get-Date -Format s)] Register event..."
        $onChange = Register-ObjectEvent $watcher Changed -Action { $global:FileChanged = $true }
        Log info "::: [$(Get-Date -Format s)] Register event... Done."
        [System.Console]::TreatControlCAsInput = $true

        try {
            while ($tru ) {
                if ($global:FileChanged) {
                    ++$executeCounter
                    Log info "::: [$(Get-Date -Format s)] Execute (${executeCounter}): ${Action}"
                    & $scriptBlock
                    $global:FileChanged = $false
                    Log info "::: [$(Get-Date -Format s)] Execution (${executeCounter}) Done."
                }

                if ($Host.UI.RawUI.KeyAvailable -and (3 -eq [int]$Host.UI.RawUI.ReadKey('AllowCtrlC, IncludeKeyUp, NoEcho').Character)) {
                    Log info "::: [$(Get-Date -Format s)] Unregister event..."
                    Unregister-Event -SourceIdentifier $onChange.Name
                    Log info "::: [$(Get-Date -Format s)] Unregister event... Done."
                    return
                }

                Start-Sleep -Milliseconds $PoolingIntervalInMS
            }
        } catch [Exception] {
            Log info "::: [$(Get-Date -Format s)] Unregister event..."
            Unregister-Event -SourceIdentifier $onChange.Name
            Log info "::: [$(Get-Date -Format s)] Unregister event... Done."
        }
    }

    End {
        [System.Console]::TreatControlCAsInput = $false
    }
}
# SIG # Begin signature block
# MIIcjgYJKoZIhvcNAQcCoIIcfzCCHHsCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDIsS/JadE+BhwQ
# Xnaq6eTMEYeJI2/k7oHGrtRP5qwa9KCCF5gwggUhMIIECaADAgECAhAIWwDz5iwy
# UtohxU7HR7bMMA0GCSqGSIb3DQEBCwUAMHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNV
# BAMTKERpZ2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBDb2RlIFNpZ25pbmcgQ0EwHhcN
# MTkwMzEyMDAwMDAwWhcNMjAwMzE2MTIwMDAwWjBeMQswCQYDVQQGEwJERTEfMB0G
# A1UEBxMWR2FybWlzY2gtUGFydGVua2lyY2hlbjEWMBQGA1UEChMNTWFudWVsIFRh
# bnplcjEWMBQGA1UEAxMNTWFudWVsIFRhbnplcjCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBAPIHE2FyXkrHpGfPf80N/4sJPgORb+Br0+wCuJSD8BMRNB40
# 1Rmn2dcq7IEfvud6qCdnxo/jLmTWNiEb7dr+NcRvIggi5yUM48DjpUnYpsDAIVTQ
# 1j1+X7DgaCy7KrR9qsJciYvsZqjFOG7vHdOfU8LUaGD+eKHlL8uKOAdgHT7KnNJi
# QQtK1fK2D0MUK+CqBuFg4m+XDfQbugzi5w9YkbdlIaQoxjVWogDqG9fs60501ly6
# yDrS4oOQFnHWcx1HlWFrGPU6kMMdDLeVC211qbIMFH+z8Rc+aSWzXBlxn9TUygJW
# ghkNTGS/2C34RjtQDK/4rl2Koh7NHqCUMJf1bIECAwEAAaOCAcUwggHBMB8GA1Ud
# IwQYMBaAFFrEuXsqCqOl6nEDwGD5LfZldQ5YMB0GA1UdDgQWBBSjqX8VbvlnZ2WB
# n2oo/qfn1g674TAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMw
# dwYDVR0fBHAwbjA1oDOgMYYvaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL3NoYTIt
# YXNzdXJlZC1jcy1nMS5jcmwwNaAzoDGGL2h0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNv
# bS9zaGEyLWFzc3VyZWQtY3MtZzEuY3JsMEwGA1UdIARFMEMwNwYJYIZIAYb9bAMB
# MCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwCAYG
# Z4EMAQQBMIGEBggrBgEFBQcBAQR4MHYwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3Nw
# LmRpZ2ljZXJ0LmNvbTBOBggrBgEFBQcwAoZCaHR0cDovL2NhY2VydHMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0U0hBMkFzc3VyZWRJRENvZGVTaWduaW5nQ0EuY3J0MAwG
# A1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAOIRTvC2IfJXdRz46zRs+4+z
# YKsufAnKNlAkgMc4cX2NKD/u5kvB1aS1EFAE9vRLPURtDgiLia6I8nLOUag4iWpO
# mH9nd8utH+obJhR3l35jB8WP/RVdcRU9GicRT9ARWLZEby6CYpq081WNCtxoPCEs
# +bAiCBcR6KkWP5YUGoC0tBn5aeoTmpJgtLjGGjtsHQH9Xoak7T39gjbJZLoztVfE
# A78MSmjvTvVyn4SfgVT31y9puQxMwusrZf+axm51SJp0YTYVAuHtNVqfxve4QBXq
# 6OXtGnceVuEmcH9cSRYo5GOhuNyq4yIq1/yLIWeLiBxlqaKauSPPG8yCaXFs1LEw
# ggUwMIIEGKADAgECAhAECRgbX9W7ZnVTQ7VvlVAIMA0GCSqGSIb3DQEBCwUAMGUx
# CzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3
# dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9v
# dCBDQTAeFw0xMzEwMjIxMjAwMDBaFw0yODEwMjIxMjAwMDBaMHIxCzAJBgNVBAYT
# AlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2Vy
# dC5jb20xMTAvBgNVBAMTKERpZ2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBDb2RlIFNp
# Z25pbmcgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD407Mcfw4R
# r2d3B9MLMUkZz9D7RZmxOttE9X/lqJ3bMtdx6nadBS63j/qSQ8Cl+YnUNxnXtqrw
# nIal2CWsDnkoOn7p0WfTxvspJ8fTeyOU5JEjlpB3gvmhhCNmElQzUHSxKCa7JGnC
# wlLyFGeKiUXULaGj6YgsIJWuHEqHCN8M9eJNYBi+qsSyrnAxZjNxPqxwoqvOf+l8
# y5Kh5TsxHM/q8grkV7tKtel05iv+bMt+dDk2DZDv5LVOpKnqagqrhPOsZ061xPeM
# 0SAlI+sIZD5SlsHyDxL0xY4PwaLoLFH3c7y9hbFig3NBggfkOItqcyDQD2RzPJ6f
# pjOp/RnfJZPRAgMBAAGjggHNMIIByTASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1Ud
# DwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDAzB5BggrBgEFBQcBAQRtMGsw
# JAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcw
# AoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElE
# Um9vdENBLmNydDCBgQYDVR0fBHoweDA6oDigNoY0aHR0cDovL2NybDQuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDA6oDigNoY0aHR0cDov
# L2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDBP
# BgNVHSAESDBGMDgGCmCGSAGG/WwAAgQwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93
# d3cuZGlnaWNlcnQuY29tL0NQUzAKBghghkgBhv1sAzAdBgNVHQ4EFgQUWsS5eyoK
# o6XqcQPAYPkt9mV1DlgwHwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8w
# DQYJKoZIhvcNAQELBQADggEBAD7sDVoks/Mi0RXILHwlKXaoHV0cLToaxO8wYdd+
# C2D9wz0PxK+L/e8q3yBVN7Dh9tGSdQ9RtG6ljlriXiSBThCk7j9xjmMOE0ut119E
# efM2FAaK95xGTlz/kLEbBw6RFfu6r7VRwo0kriTGxycqoSkoGjpxKAI8LpGjwCUR
# 4pwUR6F6aGivm6dcIFzZcbEMj7uo+MUSaJ/PQMtARKUT8OZkDCUIQjKyNookAv4v
# cn4c10lFluhZHen6dGRrsutmQ9qzsIzV6Q3d9gEgzpkxYz0IGhizgZtPxpMQBvwH
# gfqL2vmCSfdibqFT+hKUGIUukpHqaGxEMrJmoecYpJpkUe8wggZqMIIFUqADAgEC
# AhADAZoCOv9YsWvW1ermF/BmMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
# b20xITAfBgNVBAMTGERpZ2lDZXJ0IEFzc3VyZWQgSUQgQ0EtMTAeFw0xNDEwMjIw
# MDAwMDBaFw0yNDEwMjIwMDAwMDBaMEcxCzAJBgNVBAYTAlVTMREwDwYDVQQKEwhE
# aWdpQ2VydDElMCMGA1UEAxMcRGlnaUNlcnQgVGltZXN0YW1wIFJlc3BvbmRlcjCC
# ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKNkXfx8s+CCNeDg9sYq5kl1
# O8xu4FOpnx9kWeZ8a39rjJ1V+JLjntVaY1sCSVDZg85vZu7dy4XpX6X51Id0iEQ7
# Gcnl9ZGfxhQ5rCTqqEsskYnMXij0ZLZQt/USs3OWCmejvmGfrvP9Enh1DqZbFP1F
# I46GRFV9GIYFjFWHeUhG98oOjafeTl/iqLYtWQJhiGFyGGi5uHzu5uc0LzF3gTAf
# uzYBje8n4/ea8EwxZI3j6/oZh6h+z+yMDDZbesF6uHjHyQYuRhDIjegEYNu8c3T6
# Ttj+qkDxss5wRoPp2kChWTrZFQlXmVYwk/PJYczQCMxr7GJCkawCwO+k8IkRj3cC
# AwEAAaOCAzUwggMxMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYGA1Ud
# JQEB/wQMMAoGCCsGAQUFBwMIMIIBvwYDVR0gBIIBtjCCAbIwggGhBglghkgBhv1s
# BwEwggGSMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BT
# MIIBZAYIKwYBBQUHAgIwggFWHoIBUgBBAG4AeQAgAHUAcwBlACAAbwBmACAAdABo
# AGkAcwAgAEMAZQByAHQAaQBmAGkAYwBhAHQAZQAgAGMAbwBuAHMAdABpAHQAdQB0
# AGUAcwAgAGEAYwBjAGUAcAB0AGEAbgBjAGUAIABvAGYAIAB0AGgAZQAgAEQAaQBn
# AGkAQwBlAHIAdAAgAEMAUAAvAEMAUABTACAAYQBuAGQAIAB0AGgAZQAgAFIAZQBs
# AHkAaQBuAGcAIABQAGEAcgB0AHkAIABBAGcAcgBlAGUAbQBlAG4AdAAgAHcAaABp
# AGMAaAAgAGwAaQBtAGkAdAAgAGwAaQBhAGIAaQBsAGkAdAB5ACAAYQBuAGQAIABh
# AHIAZQAgAGkAbgBjAG8AcgBwAG8AcgBhAHQAZQBkACAAaABlAHIAZQBpAG4AIABi
# AHkAIAByAGUAZgBlAHIAZQBuAGMAZQAuMAsGCWCGSAGG/WwDFTAfBgNVHSMEGDAW
# gBQVABIrE5iymQftHt+ivlcNK2cCzTAdBgNVHQ4EFgQUYVpNJLZJMp1KKnkag0v0
# HonByn0wfQYDVR0fBHYwdDA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0QXNzdXJlZElEQ0EtMS5jcmwwOKA2oDSGMmh0dHA6Ly9jcmw0LmRp
# Z2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRENBLTEuY3JsMHcGCCsGAQUFBwEB
# BGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsG
# AQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1
# cmVkSURDQS0xLmNydDANBgkqhkiG9w0BAQUFAAOCAQEAnSV+GzNNsiaBXJuGziMg
# D4CH5Yj//7HUaiwx7ToXGXEXzakbvFoWOQCd42yE5FpA+94GAYw3+puxnSR+/iCk
# V61bt5qwYCbqaVchXTQvH3Gwg5QZBWs1kBCge5fH9j/n4hFBpr1i2fAnPTgdKG86
# Ugnw7HBi02JLsOBzppLA044x2C/jbRcTBu7kA7YUq/OPQ6dxnSHdFMoVXZJB2vkP
# gdGZdA0mxA5/G7X1oPHGdwYoFenYk+VVFvC7Cqsc21xIJ2bIo4sKHOWV2q7ELlmg
# Yd3a822iYemKC23sEhi991VUQAOSK2vCUcIKSK+w1G7g9BQKOhvjjz3Kr2qNe9zY
# RDCCBs0wggW1oAMCAQICEAb9+QOWA63qAArrPye7uhswDQYJKoZIhvcNAQEFBQAw
# ZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBS
# b290IENBMB4XDTA2MTExMDAwMDAwMFoXDTIxMTExMDAwMDAwMFowYjELMAkGA1UE
# BhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2lj
# ZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgQXNzdXJlZCBJRCBDQS0xMIIBIjAN
# BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6IItmfnKwkKVpYBzQHDSnlZUXKnE
# 0kEGj8kz/E1FkVyBn+0snPgWWd+etSQVwpi5tHdJ3InECtqvy15r7a2wcTHrzzpA
# DEZNk+yLejYIA6sMNP4YSYL+x8cxSIB8HqIPkg5QycaH6zY/2DDD/6b3+6LNb3Mj
# /qxWBZDwMiEWicZwiPkFl32jx0PdAug7Pe2xQaPtP77blUjE7h6z8rwMK5nQxl0S
# QoHhg26Ccz8mSxSQrllmCsSNvtLOBq6thG9IhJtPQLnxTPKvmPv2zkBdXPao8S+v
# 7Iki8msYZbHBc63X8djPHgp0XEK4aH631XcKJ1Z8D2KkPzIUYJX9BwSiCQIDAQAB
# o4IDejCCA3YwDgYDVR0PAQH/BAQDAgGGMDsGA1UdJQQ0MDIGCCsGAQUFBwMBBggr
# BgEFBQcDAgYIKwYBBQUHAwMGCCsGAQUFBwMEBggrBgEFBQcDCDCCAdIGA1UdIASC
# AckwggHFMIIBtAYKYIZIAYb9bAABBDCCAaQwOgYIKwYBBQUHAgEWLmh0dHA6Ly93
# d3cuZGlnaWNlcnQuY29tL3NzbC1jcHMtcmVwb3NpdG9yeS5odG0wggFkBggrBgEF
# BQcCAjCCAVYeggFSAEEAbgB5ACAAdQBzAGUAIABvAGYAIAB0AGgAaQBzACAAQwBl
# AHIAdABpAGYAaQBjAGEAdABlACAAYwBvAG4AcwB0AGkAdAB1AHQAZQBzACAAYQBj
# AGMAZQBwAHQAYQBuAGMAZQAgAG8AZgAgAHQAaABlACAARABpAGcAaQBDAGUAcgB0
# ACAAQwBQAC8AQwBQAFMAIABhAG4AZAAgAHQAaABlACAAUgBlAGwAeQBpAG4AZwAg
# AFAAYQByAHQAeQAgAEEAZwByAGUAZQBtAGUAbgB0ACAAdwBoAGkAYwBoACAAbABp
# AG0AaQB0ACAAbABpAGEAYgBpAGwAaQB0AHkAIABhAG4AZAAgAGEAcgBlACAAaQBu
# AGMAbwByAHAAbwByAGEAdABlAGQAIABoAGUAcgBlAGkAbgAgAGIAeQAgAHIAZQBm
# AGUAcgBlAG4AYwBlAC4wCwYJYIZIAYb9bAMVMBIGA1UdEwEB/wQIMAYBAf8CAQAw
# eQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2Vy
# dC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9E
# aWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwgYEGA1UdHwR6MHgwOqA4oDaGNGh0
# dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5j
# cmwwOqA4oDaGNGh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3Vy
# ZWRJRFJvb3RDQS5jcmwwHQYDVR0OBBYEFBUAEisTmLKZB+0e36K+Vw0rZwLNMB8G
# A1UdIwQYMBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMA0GCSqGSIb3DQEBBQUAA4IB
# AQBGUD7Jtygkpzgdtlspr1LPUukxR6tWXHvVDQtBs+/sdR90OPKyXGGinJXDUOSC
# uSPRujqGcq04eKx1XRcXNHJHhZRW0eu7NoR3zCSl8wQZVann4+erYs37iy2QwsDS
# tZS9Xk+xBdIOPRqpFFumhjFiqKgz5Js5p8T1zh14dpQlc+Qqq8+cdkvtX8JLFuRL
# cEwAiR78xXm8TBJX/l/hHrwCXaj++wc4Tw3GXZG5D2dFzdaD7eeSDY2xaYxP+1ng
# Iw/Sqq4AfO6cQg7PkdcntxbuD8O9fAqg7iwIVYUiuOsYGk38KiGtSTGDR5V3cdyx
# G0tLHBCcdxTBnU8vWpUIKRAmMYIETDCCBEgCAQEwgYYwcjELMAkGA1UEBhMCVVMx
# FTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNv
# bTExMC8GA1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIENvZGUgU2lnbmlu
# ZyBDQQIQCFsA8+YsMlLaIcVOx0e2zDANBglghkgBZQMEAgEFAKCBhDAYBgorBgEE
# AYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwG
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCkmpyy
# HVjUtesUEsFE9pyPW96AOzuB/SCJ5KPYSkEaVzANBgkqhkiG9w0BAQEFAASCAQCF
# MqALCJEGWKDtGiGhwafa4e106rDsyAj/DcM3smrk6/015ggPajTfjtKwUXoQkUeJ
# GrxA9yx3MA3LkK3d3NJ3QV4ahkNYGrNeRC3wBPY6gQIerykgK3bibtHIWdsiEAt7
# rMAuker3XtYOG4yPmsZJV0lSyYQp5JGnoQ8wyob+ZRBBAS01iJC12X7rAYYazaoO
# UYkKtr7/0Nc709qKZkVZWVKlGfugVYkQ27/vXHiBvBUHNIE6xC3TbNeUUb2w1Ate
# mUXTZoYIR1B2H7g0U3UKdNkmaaiGkX7ZpPch+V982C0GXvcpjvPRklwbOZ1HaLHK
# UbfE3NX9meU06LJRieqqoYICDzCCAgsGCSqGSIb3DQEJBjGCAfwwggH4AgEBMHYw
# YjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgQXNzdXJlZCBJRCBD
# QS0xAhADAZoCOv9YsWvW1ermF/BmMAkGBSsOAwIaBQCgXTAYBgkqhkiG9w0BCQMx
# CwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yMDAzMDkyMjE1MDlaMCMGCSqG
# SIb3DQEJBDEWBBSJG90r8rgbR7Vb+XVW3QnWdswGJDANBgkqhkiG9w0BAQEFAASC
# AQBnd/KTVVIEZbydw9/QBljEEVrvh3l9sdtABmu/3a/vcAd3clOR++AzINsZ3Iaf
# rwAcKzQen/BxKY6gW+c5nQWQvWIK8hG+VGQtP/xd5A6OpDS1/Cpa/BosmtNs7LqZ
# eXrfQaK6MeWllvLte1Pmw2Dp2flNdADIz7r+AHF5AgPGk0sYqg0U5M5bWJiq2664
# XpupepA+8fQMmDPaEUCN/e7UHhaEj8jDrjfm64K+ZOeLBqEqfdReFJPPp/4pczUV
# XZgwSFRPGEpLnVP+F7LzvZw+TCuaLxXCEp2SnF8vpaJdVjUefXuYKihzZu+L8ALF
# L/IQHe2d+Pm8ejvpfbMrVL33
# SIG # End signature block
