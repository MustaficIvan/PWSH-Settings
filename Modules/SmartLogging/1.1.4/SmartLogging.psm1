Add-Type -TypeDefinition @"
    public enum LogLevel
    {
        Trc = 0,
        Dbg = 1,
        Inf = 2,
        Wrn = 3,
        Err = 4,
        Cri = 5,
        Non = 6
    }
"@

$defaultLogLevel = [LogLevel]::Inf
$defaultLogLevelString = @{
    Short = 'inf'
    Long  = 'info'
    Color = ([ConsoleColor]::White)
}
$consoleLogDateFormat = 'HH:mm:ss'
$fileLogDateFormat = 'yyyy-MM-ddTHH:mm:ss zzz'
$fileLogger = @{ }

function GetLogLevel($logLevel) {
    switch ($logLevel) {
        ( { $logLevel -ieq 'trace' -or $logLevel -ieq 'trc' }) { return [LogLevel]::Trc }
        ( { $logLevel -ieq 'debug' -or $logLevel -ieq 'dbg' }) { return [LogLevel]::Dbg }
        ( { $logLevel -ieq 'info' -or $logLevel -ieq 'inf' }) { return [LogLevel]::Inf }
        ( { $logLevel -ieq 'warning' -or $logLevel -ieq 'wrn' }) { return [LogLevel]::Wrn }
        ( { $logLevel -ieq 'error' -or $logLevel -ieq 'err' }) { return [LogLevel]::Err }
        ( { $logLevel -ieq 'critic' -or $logLevel -ieq 'cri' }) { return [LogLevel]::Cri }
        ( { $logLevel -ieq 'none' -or $logLevel -ieq 'non' }) { return [LogLevel]::Non }
        Default { return $null }
    }
}

function GetLogLevelInfo($logLevel) {
    switch ($logLevel) {
        ([LogLevel]::Trc) {
            return @{
                Short = 'trc'
                Long  = 'trace'
                Color = ([ConsoleColor]::DarkGray)
            }
        }
        ([LogLevel]::Dbg) {
            return @{
                Short = 'dbg'
                Long  = 'debug'
                Color = ([ConsoleColor]::DarkGray)
            }
        }
        ([LogLevel]::Inf) {
            return @{
                Short = 'inf'
                Long  = 'info'
                Color = ([ConsoleColor]::White)
            }
        }
        ([LogLevel]::Wrn) {
            return @{
                Short = 'wrn'
                Long  = 'warning'
                Color = ([ConsoleColor]::Yellow)
            }
        }
        ([LogLevel]::Err) {
            return @{
                Short = 'err'
                Long  = 'error'
                Color = ([ConsoleColor]::Red)
            }
        }
        ([LogLevel]::Cri) {
            return @{
                Short = 'cri'
                Long  = 'critical'
                Color = ([ConsoleColor]::Red)
            }
        }
        ([LogLevel]::Non) {
            return @{
                Short = 'non'
                Long  = 'none'
                Color = ([ConsoleColor]::White)
            }
        }
        Default { return $defaultLogLevelString }
    }
}

function GetUserLogLevel() {
    $userLogLevel = $env:LOGLEVEL
    if (-not $userLogLevel) {
        $userLogLevel = $defaultLogLevel
    }

    return (GetLogLevel $userLogLevel)
}

function ShouldLog($userLogLevel, $logLevel) {
    switch ($userLogLevel) {
        ( { ($logLevel.value__ -ge $userLogLevel.value__) -and ($userLogLevel -ne [LogLevel]::Non) -and ($logLevel -ne [LogLevel]::Non) }) { return $true }
        Default { return $false }
    }
}

function LogConsole($logLevelInfo, $value) {
    Write-Host "[$(Get-Date -Format $consoleLogDateFormat) " -NoNewline -ForegroundColor ([ConsoleColor]::DarkGray)

    Write-Host "$($logLevelInfo.Short.ToUpper())" -NoNewline -ForegroundColor $logLevelInfo.Color
    Write-Host "] " -NoNewline -ForegroundColor ([ConsoleColor]::DarkGray)
    Write-Host $value -ForegroundColor ([ConsoleColor]::White)
}

function LogFile($logLevelInfo, $value) {
    # Check logs folder and create when not exists
    $date = '{0:yyyy-MM-dd}' -f (Get-Date)
    if (-not ( Test-Path -Path $fileLogger.Dir -PathType Container)) {
        New-Item -Path $fileLogger.Dir -ItemType Container > $null
    }

    # Create log file in format '{current_date}_[${filelogger.FileName}].log'
    if ($fileLogger.FileName) {
        $logfile = "$date`_$($fileLogger.FileName).log"
    } else {
        $logfile = "$date.log"
    }

    $logFilePath = Join-Path $fileLogger.Dir $logfile

    $item = "[$(Get-Date -Format $fileLogDateFormat) "
    $item += "$($logLevelInfo.Long.ToUpper())]".PadRight(9)
    $item += " "
    $item += $value

    Add-Content -Path $logFilePath -Value "$item" -Encoding ascii > $null
}

function Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object] $Value,

        [Parameter(ValueFromPipeline)]
        [object] $LogLevel
    )

    begin {
        Write-Verbose "[begin]   Value:    $Value"
        Write-Verbose "[begin]   LogLevel: $LogLevel"

        $orgLogLevel = $LogLevel

        $level = $null
        if (-not $LogLevel -and -not $Value) {
            $level = $defaultLogLevel
        } elseif ($LogLevel -and -not $Value) {
            $level = GetLogLevel $LogLevel
        } elseif (-not $LogLevel -and $Value) {
            $level = GetLogLevel $Value
        } elseif ($LogLevel -and $Value) {
            $level = GetLogLevel $LogLevel
            if ($level -eq $null) {
                $level = GetLogLevel $Value
                $Value = $LogLevel
            }
        }

        if ($level -eq $null) {
            $level = $defaultLogLevel
        }

        Write-Verbose "[begin]   level: $level"
    }

    process {
        Write-Verbose "[process] Value:    $Value"
        Write-Verbose "[process] LogLevel: $LogLevel"
        Write-Verbose "[process] level: $level"

        if ($orgLogLevel -ne $LogLevel) {
            $Value = $LogLevel
        }

        if (-not (ShouldLog (GetUserLogLevel) $level)) {
            return
        }

        $logLevelInfo = GetLogLevelInfo $level

        LogConsole $logLevelInfo $Value
        if ($fileLogger.IsEnabled) {
            LogFile $logLevelInfo $Value
        }
    }
}

function Set-FileLogger($Dir = 'logs', $FileName = '') {
    $Script:fileLogger.IsEnabled = $true
    $Script:fileLogger.Dir = $Dir
    $Script:fileLogger.FileName = $FileName
}

function Remove-FileLogger() {
    Set-FileLogger
    $Script:fileLogger.IsEnabled = $false
}

function Write-Status {
    [CmdletBinding()]
    param(
        [int] $Current,
        [int] $Total,
        [string] $Statustext,
        [string] $CurrentStatusText,
        [int] $ProgressbarLength = 35
    )

    # Save current Cursorposition for later
    [int] $XOrg = $Host.UI.RawUI.CursorPosition.X

    # Create Progressbar
    [string] $progressbar = ""
    for ($i = 0 ; $i -lt $([System.Math]::Round($(([System.Math]::Round(($($Current) / $Total) * 100, 2) * $ProgressbarLength) / 100), 0)); ++$i) {
        $progressbar = $progressbar + $([char]9608)
    }

    for ($i = 0 ; $i -lt ($ProgressbarLength - $([System.Math]::Round($(([System.Math]::Round(($($Current) / $Total) * 100, 2) * $ProgressbarLength) / 100), 0))); ++$i) {
        $progressbar = $progressbar + $([char]9617)
    }

    # Overwrite Current Line with the current Status
    Write-Host -NoNewline "`r$Statustext $progressbar [$($Current.ToString("#,###").PadLeft($Total.ToString("#,###").Length)) / $($Total.ToString("#,###"))] ($($(($Current / $Total) * 100).ToString("##0.00").PadLeft(6)) %) $CurrentStatusText"

    # There might be old Text behing the current Currsor, so let's write some blanks to the Position of $XOrg
    [int] $XNow = $Host.UI.RawUI.CursorPosition.X
    for ([int] $i = $XNow; $i -lt $XOrg; ++$i) {
        Write-Host -NoNewline " "
    }

    # Just for optical reasons: Go back to the last Position of current Line
    for ([int] $i = $XNow; $i -lt $XOrg; ++$i) {
        Write-Host -NoNewline "`b"
    }
}
# SIG # Begin signature block
# MIIcjgYJKoZIhvcNAQcCoIIcfzCCHHsCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCLgNlIwEaD09tu
# oJfyVBzrSkJDzxJUqErn58SEWDbSS6CCF5gwggUhMIIECaADAgECAhAIWwDz5iwy
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
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDP3mgf
# ZTns+1yWkzxwQgw8zx6lBYirYL4FYHGuGPLfhzANBgkqhkiG9w0BAQEFAASCAQB5
# u+wsDn0RTRawzd2WPfVlEKTZQn3jyNcqtQl2xTlXuzK9MqXA6y8+FLeQ2GYQXSn1
# YourdK5XXouj0LVGcQCoK9IJUYBEowvI64dLcO9Qs6I5B4gIzdcFHUH2R/4zDjB3
# 1C1TPqvBAll6Zarvb1pGOyrHriPe4mYL6m83qb9uuqGVg68jAOOwxi+t4xic9Irv
# Pu69Ik1CSDjhSC4xMPBQEa2HDJpzpSsXltWeeD6DcvCQ7Ww3NxefbLZIP8Etxx6+
# 7/miv+SdQRBgIzrPCAq3Yebw+crzm4F4IJvG8XIFeo3j3nkSaBZBSkwSSFnyQ5GO
# 6ogyNOkI/p9NdxUBdE7toYICDzCCAgsGCSqGSIb3DQEJBjGCAfwwggH4AgEBMHYw
# YjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgQXNzdXJlZCBJRCBD
# QS0xAhADAZoCOv9YsWvW1ermF/BmMAkGBSsOAwIaBQCgXTAYBgkqhkiG9w0BCQMx
# CwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xOTA0MDQxNTQ4MzJaMCMGCSqG
# SIb3DQEJBDEWBBSGK/B4nCjiR9R8JMCxj3QRUnJ/hzANBgkqhkiG9w0BAQEFAASC
# AQCK9wU1kVVH6CY+g9MpG7debdkgKdPsgBZabcxfwR7JhDsXvfdnO1v0mL3cr9jM
# dcaxkxsLGxOvMHOJ5W81VXWtN96Cq4/aHJNs9/WtL0UV2un5PK38Rb8wGDktVhv6
# bdqgFWMyftvFA5SjwQqfictZUCmACQPRGjtSWKQTpcwIwCNm5MkusyP9Kbb3z2Kd
# H2j0ZZp4g43PwrQYROMToN5RlmXNOZLoFi8pPK6Lp40IismS97BEDLgb4eAZOcKX
# HCcD1N8PrdFuHA1c3iU7PWnxdfE0RAmUlpcRujaa9gjjrzENPJ04dM+zvIkj5UcA
# JmG5QJk3IMnRO1nCShUQqLFl
# SIG # End signature block
