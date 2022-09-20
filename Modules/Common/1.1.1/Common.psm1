function New-DynamicParameter {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string] $Name,

        [Parameter()]
        [type] $Type = [string],

        [Parameter()]
        [string[]] $Alias = @(),

        [Parameter()]
        [string[]] $ValidateSet,

        [Parameter()]
        [switch] $Mandatory,

        [Parameter()]
        [string] $ParameterSetName = '__AllParameterSets',

        [Parameter()]
        [int] $Position,

        [Parameter()]
        [switch] $ValueFromPipeline,

        [Parameter()]
        [switch] $ValueFromPipelineByPropertyName,

        [Parameter()]
        [switch] $ValueFromRemainingArguments,

        [Parameter()]
        [string]
        $HelpMessage,

        [validatescript( {
                if (-not ($_ -is [System.Management.Automation.RuntimeDefinedParameterDictionary] -or -not $_)) {
                    throw "DPDictionary must be a System.Management.Automation.RuntimeDefinedParameterDictionary object, or not exist"
                }

                $true
            })]
        $DPDictionary = $null
    )

    $parameterAttribute = New-Object System.Management.Automation.ParameterAttribute

    if ($Mandatory) {
        $parameterAttribute.Mandatory = $true
    }

    if ($ParameterSetName) {
        $parameterAttribute.ParameterSetName = $ParameterSetName
    }

    if ($Position -ne $null) {
        $parameterAttribute.Position = $Position
    }

    if ($ValueFromPipeline) {
        $parameterAttribute.ValueFromPipeline = $true
    }

    if ($ValueFromPipelineByPropertyName) {
        $parameterAttribute.ValueFromPipelineByPropertyName = $true
    }

    if ($ValueFromRemainingArguments) {
        $parameterAttribute.ValueFromRemainingArguments = $true
    }

    if ($HelpMessage) {
        $parameterAttribute.HelpMessage = $HelpMessage
    }

    $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
    $attributeCollection.Add($parameterAttribute)

    if ($ValidateSet) {
        $validateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($ValidateSet)
        $attributeCollection.Add($validateSetAttribute)
    }

    if ($Alias.count -gt 0) {
        $aliasAttribute = New-Object System.Management.Automation.AliasAttribute($Alias)
        $attributeCollection.Add($aliasAttribute)
    }

    $runtimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($Name, $Type, $attributeCollection)
    # $runtimeParameter.Value = '<DefaultValue>'

    if ($DPDictionary) {
        $DPDictionary.Add($Name, $runtimeParameter)
    } else {
        $runtimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        $runtimeParameterDictionary.Add($Name, $runtimeParameter)
        return $runtimeParameterDictionary
    }
}

function Get-Base64FromValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Value,

        [Parameter()]
        [ValidateSet('utf-16', 'utf-16BE', 'utf-32', 'utf-32BE', 'us-ascii', 'iso-8859-1', 'utf-7', 'utf-8')]
        [string] $Encoding = 'utf-8'
    )

    $encodingProvider = [System.Text.Encoding]::GetEncoding($Encoding)
    $base64 = [System.Convert]::ToBase64String($encodingProvider.GetBytes($Value))
    return $base64
}

function Add-ReadmeFile {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string] $FileName = 'README.md',

        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string] $Content = $null,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch] $Edit = $false
    )

    Begin {
        $lines = @()
    }

    Process {
        if (-not $Content) {
            $Content = @'
# Project Name

TODO: Write a project description

## Installation

TODO: Describe the installation process

## Usage

TODO: Write usage instructions

## Contributing

1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request :D

## History

TODO: Write history

## Credits

TODO: Write credits

## License

TODO: Write license

'@
        }

        $lines += $Content
    }

    End {
        $path = (Get-Location)
        $filePath = Join-Path $path $FileName

        $utf8NoBomEncoding = New-Object System.Text.UTF8Encoding($false)

        if ($lines -and $lines.Count -gt 1) {
            [System.IO.File]::WriteAllLines($filePath, $lines, $utf8NoBomEncoding) > $null
        } else {
            [System.IO.File]::WriteAllText($filePath, $lines, $utf8NoBomEncoding) > $null
        }

        Log info "Created file '${filePath}'"

        if ($Edit.isPresent -or $Edit) {
            & $filePath
        }
    }
}

function fn_add_readmefile_edit { Add-ReadmeFile -Edit }

function Get-Checksum {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'set1')]
        [string] $Value,

        [Parameter(Mandatory, Position = 1, ParameterSetName = 'set2')]
        [string] $File,

        [Parameter(Position = 2)]
        [ValidateSet('MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512')]
        [string] $Algorithm = 'SHA256'
    )

    Begin {
        $hashAlgorithm = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)
    }

    Process {
        $sb = [System.Text.StringBuilder]::new(50)

        if (-not $Value -and -not $File) {
            return
        }

        try {
            if ($File) {
                $File = Resolve-Path $File

                try {
                    [System.IO.FileStream]$fileStream = [System.IO.File]::Open($File, [System.IO.FileMode]::Open);
                    $hashAlgorithm.ComputeHash($fileStream) | ForEach-Object { $sb.Append($_.ToString('x2')) > $null }
                } catch {
                    Log error "Error reading or hashing file '$File'"
                    Log error $_
                } finally {
                    $fileStream.Close()
                    $fileStream.Dispose()
                }
            } elseif ($Value) {
                $hashAlgorithm.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Value)) | ForEach-Object { $sb.Append($_.ToString('x2')) > $null }
            }
        } catch {
            Log error "Something went wrong: $_"
        }

        return $sb.ToString()
    }
}

function New-DirectoryAndEnter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    New-Item -Path $Path -ItemType Directory
    Set-Location -Path $Path
}

function Search-ReplaceInFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]] $Files,

        [Parameter()]
        [string] $SearchValue,

        [Parameter()]
        [string] $ReplaceValue,

        [Parameter()]
        [switch] $WhatIf
    )

    foreach ($file in $Files) {
        $filePath = Resolve-Path $file

        $content = Get-Content $filePath -Raw

        if (-not $SearchValue -and -not $ReplaceValue) {
            Write-Host $content
            return
        }

        $newContent = $content.Replace($SearchValue, $ReplaceValue)

        if (-not $content.Contains($SearchValue)) {
            Log info "File '$filePath' doesn't contains the value '$SearchValue'."
            Log info 'Nothing changed.'
            return
        }

        if ($WhatIf.isPresent) {
            Write-Host $newContent
            Write-Host
            Log info "Nothing changed in '$filePath'."
        } else {
            Set-Content -Path $filePath -Value $newContent -NoNewline > $null
            Log info "Replaced in '$filePath'."
        }
    }
}

function Invoke-CmdScript([string] $file, [string] $parameters) {
    & "${env:COMSPEC}" /s /c "`"$file`" ${parameters} -no_logo && set" | ForEach-Object {
        # $name, $value = $_ -split '=', 2
        # set-content Env:\"$name" $value
        if ($_ -match '^(.*?)=(.*)$') {
            Set-Content "Env:\$($matches[1])" $matches[2]
        }
    }
}

New-Alias arf Add-ReadmeFile
New-Alias arfe fn_add_readmefile_edit
New-Alias mcd New-DirectoryAndEnter
New-Alias sr Search-ReplaceInFile
# SIG # Begin signature block
# MIIcjgYJKoZIhvcNAQcCoIIcfzCCHHsCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDVbdMXJaDTmchV
# jLzu7tiMKo2NQbUDJf5zPmxxxcH+pKCCF5gwggUhMIIECaADAgECAhAIWwDz5iwy
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
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBDBjaG
# nQCLgdDWUc4ujoWSCxhyXR6u46QS1lanO4iReTANBgkqhkiG9w0BAQEFAASCAQCw
# 6X4+tbQQ9atY6Wbr3jSKnvQYMteLn4dhzcOBuUWKqILhglnF1Lfui0bevVuS5wK5
# YSaAxIIevuj0wv+C9P1XB2zrrFzmn/h35Y35zWROxlgsYVIW9STG0E+A8yoSDVrp
# B8B2NxpVnP/Jl8zaGR+EkHPYql0EnA4YG9BplLxAboIQQVOOEsHkStAeJujbbUfp
# HFjCnkVm7W/ohpa503zm1KsziKUIH95sw4+NbiWTiZiQ3N2QfAnyf90+NDvJXI1Z
# lYuEeGd3OsAu+aStohMdoZJsvszXclbLtQ3Ty5CJqMFgLMIsWgJb4uawlUl6sUhg
# pa5oh64Zo1mUxVKte1j6oYICDzCCAgsGCSqGSIb3DQEJBjGCAfwwggH4AgEBMHYw
# YjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgQXNzdXJlZCBJRCBD
# QS0xAhADAZoCOv9YsWvW1ermF/BmMAkGBSsOAwIaBQCgXTAYBgkqhkiG9w0BCQMx
# CwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yMDAzMDkyMjI1MjdaMCMGCSqG
# SIb3DQEJBDEWBBRX+5K9gggXAH2hBzo03Nt/d2dYajANBgkqhkiG9w0BAQEFAASC
# AQCVpA0K09rHnsKKdMIdQuAt8sq10ZOnQzknXVquRoIpjgsmc2mWeJHrRk0SFzhn
# No5Y7T3xYx2X63nDfWuiNphXvrpiDhC1kFMgj7+gjmR+EzSKqFqPrSh9GaO7fu/A
# 9ezjc1pQ4Iz58y3A+6Rpz+o3EWhwKIXyRpxbx+0Hkvu/dSsDQ2ChW+AfgXommNFq
# YZ4ATBJ0bcC49zVa0didLhGYmr7+sR7ElXKBVbZYMDcEcKbz1BVcGhTRAB3ZiNNE
# HZFjelW1zvokf/bMqKTmBSIVAflTG7ygbIwGvPUZPFoFLkcDYYwZLg0g7D4Be9rA
# ZEgJ/mDMo7w5jrJqbrqx49QU
# SIG # End signature block
