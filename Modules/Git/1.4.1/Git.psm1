function Add-GitTag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Version
    )

    $tagName = "v$Version"
    $sha = Start-NativeExecution git rev-parse HEAD
    $shortSha = $shortSha = $sha.Substring(0, 8)
    $commitMessage = "Added tag $tagName for changeset $shortSha"

    Log info $commitMessage
    Start-NativeExecution git tag -a $tagName -m $commitMessage
}

function Clear-GitBranches {
    [CmdletBinding()]
    param(
        [switch] $IncludeGoneRemoteBranches
    )

    $currentBranch = Start-NativeExecution git rev-parse --abbrev-ref HEAD
    if ($LASTEXITCODE -ne 0) {
        Log warning "Error on getting the current branch. Are you outside of a Git repository?"
        Log trace "$currentBranch"
        return
    }

    Log info "Searching for branches which already merged into '$currentBranch'..."

    $branches = @{ }

    # 1. Try the default way (no remote rebased branches can be detected)
    $mergedBranches = Get-GitMergedBranches
    $mergedBranches | ForEach-Object { Log trace "Branch found with Git default logic: '$_'" }
    if ($mergedBranches) {
        $branches.Add('default logic', $mergedBranches) > $null
    }

    # 2. Try the custom way (check each hash, also remote rebased branches can be detected)
    $mergedOrRebasedBranches = Get-GitMergedOrRebasedBranches
    $mergedOrRebasedBranches | ForEach-Object { Log trace "Branch found with Git deeper logic: '$_'" }
    if ($mergedOrRebasedBranches) {
        $branches.Add('deep logic', $mergedOrRebasedBranches) > $null
    }

    if ($IncludeGoneRemoteBranches) {
        # 3. Get also remote gone branches
        $remoteGoneBranches = Get-GitRemoteGoneBranches
        $remoteGoneBranches | ForEach-Object { Log trace "Branch found with Git remote gone logic: '$_'" }
        if ($remoteGoneBranches) {
            $branches.Add('gone logic', $remoteGoneBranches) > $null
        }
    }

    # Filter out duplicates
    $uniqueMergedBranches = Get-Distincted @($mergedBranches, $mergedOrRebasedBranches, $remoteGoneBranches) | Sort-Object
    if (-not $uniqueMergedBranches) {
        Log info 'No merged branches were found'
        return
    }

    $sb = [System.Text.StringBuilder]::new()
    $prefix = 'Merged branch:'
    $logicColumn = ($uniqueMergedBranches | Sort-Object Length -Descending | Select-Object -First 1).Length + 2
    foreach ($branch in $uniqueMergedBranches) {
        $logics = Get-Logics -groupedBranches $branches -branchName $branch

        $sb.Clear() > $null
        $sb.Append(("$prefix {0,-$logicColumn} {1}" -f "'$($branch)'", "[detected by: $($logics -join ', ')]")) > $null

        Log info $sb.ToString()
    }

    $title = 'Delete merged branches'
    $message = 'Do you want to delete the already-merged local branches displayed above?'
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Delete the remote branches listed.'
    $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'Leave the branches alone.'
    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

    $result = $Host.UI.PromptForChoice($title, $message, $options, 1)
    if ($result -eq 1) {
        return
    }

    $uniqueMergedBranches | ForEach-Object { Start-NativeExecution git branch -D $_ | Log info }
}

function Get-GitMergedBranches() {
    $mergedBranches = [System.Collections.ArrayList]@()
    $branches = Start-NativeExecution git branch --merged
    if ($LASTEXITCODE -ne 0) {
        Log trace "Error on getting merged branches: $branches"
        return
    }

    $filteredBranches = $branches | Where-Object { $_ -notmatch '^\* master$' } | Where-Object { $_ -notmatch '^master$' } | Where-Object { $_ -notmatch '^\* *$' } | ForEach-Object { $_.Trim() }

    foreach ($branch in $filteredBranches) {
        Log trace "Branch already merged '$branch'"
        $mergedBranches.Add($branch) > $null
    }

    return $mergedBranches
}

function Get-GitMergedOrRebasedBranches() {
    $currentBranch = Start-NativeExecution git rev-parse --abbrev-ref HEAD
    if ($LASTEXITCODE -ne 0) {
        Log trace "Error on getting merged or rebased branches: $currentBranch"
        return
    }

    Log trace "currentBranch: '$currentBranch'"

    $currentLocalBranch = Start-NativeExecution git symbolic-ref -q HEAD
    if ($LASTEXITCODE -ne 0) {
        Log trace "Error on getting merged or rebased branches: $currentLocalBranch"
        return
    }

    Log trace "currentLocalBranch: '$currentLocalBranch'"

    $currentRemoteBranch = Start-NativeExecution git for-each-ref '--format="%(upstream:short)"' $currentLocalBranch
    if ($LASTEXITCODE -ne 0) {
        Log trace "Error on getting merged or rebased branches: $currentRemoteBranch"
        return
    }

    Log trace "currentRemoteBranch: '$currentRemoteBranch'"

    $mergedbranches = [System.Collections.ArrayList]@()

    $localBranches = Start-NativeExecution git for-each-ref refs/heads '--format="%(refname:short)"' | Where-Object { $_ -notmatch 'master' } | Where-Object { $_ -notmatch $currentBranch }
    if ($LASTEXITCODE -ne 0) {
        Log trace "Error on getting merged or rebased branches: $localBranches"
        return
    }

    foreach ($localBranch in $localBranches) {
        $notMergedHashFound = $false
        Log trace "Check local branch '$localBranch'..."
        $results = Start-NativeExecution git cherry $currentRemoteBranch $localBranch
        if ($LASTEXITCODE -ne 0) {
            Log trace "Get merged hashes failed: '$results'"
            break
        }

        foreach ($result in $results) {
            if ($result -match '^\-') {
                Log trace "Hash merged '$result'"
                continue
            }

            if ($result -match '^\+') {
                Log trace "Hash was not merged '$result'"
            } else {
                Log trace "No hash '$result'"
            }

            $notMergedHashFound = $true
            break
        }

        if (-not $notMergedHashFound) {
            Log trace "Branch already merged '$localBranch'"
            $mergedbranches.Add($localBranch) > $null
        }
    }

    return $mergedbranches
}

function Get-GitRemoteGoneBranches() {
    $goneBranches = [System.Collections.ArrayList]@()
    $branches = Start-NativeExecution git branch -v
    if ($LASTEXITCODE -ne 0) {
        Log trace "Error on getting remote gone branches: $branches"
        return
    }

    $filteredBranches = $branches | Where-Object { $_ -notmatch '\* master' } | Where-Object { $_ -notmatch 'master' } | Where-Object { $_ -notmatch '\* *' } | Where-Object { $_ -match '^.*\[gone\].*' } | ForEach-Object { $_.Trim() }
    if (-not $filteredBranches) {
        Log trace "No remote gone branches found"
        return
    }

    $filteredBranchNames = $filteredBranches | ForEach-Object { $_.Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries)[0] }
    foreach ($branchName in $filteredBranchNames) {
        Log trace "Branch is removed on remote '$branchName'"
        $goneBranches.Add($branchName) > $null
    }

    return $goneBranches
}

function Get-Distincted {
    param(
        [Parameter()]
        [object[][]] $Items
    )

    $hashSet = [System.Collections.Generic.HashSet[System.Object]]::new()
    foreach ($item in $Items) {
        foreach ($entry in $item) {
            $hashSet.Add($entry) > $null
        }
    }

    $distinctedList = [System.Collections.ArrayList]@()
    foreach ($value in $hashSet) {
        $distinctedList.Add($value) > $null
    }

    return $distinctedList
}

function Get-Logics([hashtable] $groupedBranches, [string] $branchName) {
    $logics = [System.Collections.ArrayList]@()

    foreach ($logic in $groupedBranches.GetEnumerator()) {
        [object[]] $values = $logic.Value
        if ($values.Contains($branchName)) {
            $logics.Add($logic.Name) > $null
        }
    }

    return $logics
}

function Invoke-GitkAll() {
    Invoke-Gitk -All @args
}

function Invoke-Gitk() {
    param(
        [switch] $All
    )

    $command = 'gitk'
    $arguments = [System.Collections.ArrayList]@()

    if ($All) {
        $arguments.Add('--all') > $null
    }

    $arguments += $args
    Start-NativeExecution $command @arguments
}

function Merge-GitAllRemoteBranches($RemoteRefs = $null, $Strategie = 'recursive', [switch] $UseTheirs = $false, [switch] $UseOurs = $false) {
    if ($null -eq $RemoteRefs) {
        $RemoteRefs = 'origin/'
    }

    $currentBranch = (git rev-parse --abbrev-ref HEAD).Trim()

    git fetch --all
    git branch -r | ForEach-Object {
        $localBranch = $_
        $localBranch = $localBranch.Trim().Replace($RemoteRefs, '').Trim()
        $localBranch = $localBranch.Trim().Replace('*', '').Trim()
        $remoteBranch = $_.Trim().Replace('*', '').Trim()
        if ($remoteBranch.StartsWith($RemoteRefs) -and -not $remoteBranch.StartsWith($RemoteRefs + 'HEAD')) {
            Log info "Processing branch '${localBranch}'..."
            git checkout $localBranch

            if ($UseTheirs) {
                git merge $remoteBranch -s $Strategie -X theirs
            } elseif ($UseOurs) {
                git merge $remoteBranch -s $Strategie -X ours
            } else {
                git merge $remoteBranch
            }
        }
    }

    git checkout $currentBranch
}

function Merge-GitBranchUseTheirs($SourceBranchName, $DestinationBranchName) {
    if (($null -eq $SourceBranchName) -or ($null -eq $DestinationBranchName)) {
        return
    }

    $currentBranch = (git rev-parse --abbrev-ref HEAD).Trim()
    $tempHash = Get-Checksum -Value ([System.Guid]::NewGuid()) -Algorithm SHA1
    $tempBranchName = "merge-use-theirs-${tempHash}"
    $commitMessage = "Merge branch '${SourceBranchName}' into '${DestinationBranchName}'"

    git checkout -b $tempBranchName $SourceBranchName
    git merge --strategy=ours $DestinationBranchName
    git checkout $DestinationBranchName
    git merge --no-ff $tempBranchName -m $commitMessage
    git branch -D $tempBranchName

    git checkout $currentBranch
}

function Push-GitAllTrackedBranches($RemoteRefs) {
    if ($null -eq $RemoteRefs) {
        $RemoteRefs = 'origin/'
    }

    $currentBranch = (git rev-parse --abbrev-ref HEAD).Trim()

    git branch | ForEach-Object {
        $localBranch = $_
        $localBranch = $localBranch.Trim().Replace('*', '').Trim()

        $trackingRefs = git config branch.$localBranch.merge
        if ($trackingRefs -and ($trackingRefs.Trim().StartsWith('refs/heads/' + $RemoteRefs))) {
            Log info "Processing branch '${localBranch}'..."
            git checkout $localBranch
            git push
        }
    }

    git checkout $currentBranch
}

function Remove-GitAllBranches($RemoteRefs, [switch] $ForceAll = $false) {
    if ($null -eq $RemoteRefs) {
        $RemoteRefs = 'origin/'
    }

    $currentBranch = (git rev-parse --abbrev-ref HEAD).Trim()
    $tempHash = Get-Checksum -Value ([System.Guid]::NewGuid()) -Algorithm SHA1
    $tempBranchName = "remove-all-${tempHash}"

    git checkout -f -b $tempBranchName

    git branch | ForEach-Object {
        $localBranch = $_
        $localBranch = $localBranch.Trim().Replace('*', '').Trim()

        $trackingRefs = git config branch.$localBranch.merge
        if ($trackingRefs -and ($localBranch -ne $tempBranchName) -and (($ForceAll) -or ($null -ne $trackingRefs))) {
            if (($ForceAll) -or
                ($trackingRefs.Trim().StartsWith('refs/remotes/' + $RemoteRefs)) -or
                ($trackingRefs.Trim().StartsWith('refs/heads/' + $RemoteRefs))) {
                Log info "Delete local branch '${localBranch}'..."
                git branch -D $localBranch
            }
        }
    }

    if ($ForceAll) {
        git checkout master
    } else {
        git checkout $currentBranch
    }

    git branch -D $tempBranchName
}

function Reset-GitAllBranches($RemoteRefs) {
    Remove-GitAllBranches $RemoteRefs
    Set-GitTrackAllRemoteBranches $RemoteRefs
    Merge-GitAllRemoteBranches $RemoteRefs
}

function Set-GitTrackAllRemoteBranches($RemoteRefs) {
    if ($null -eq $RemoteRefs) {
        $RemoteRefs = 'origin/'
    }

    $localBranches = git branch | ForEach-Object { $_.Trim().Replace('*', '').Trim() }

    $notTrackedLocalBranches = @()
    git for-each-ref --format='%(refname:short) <- %(upstream:short)' 'refs/heads' | ForEach-Object {
        $row = $_ -split '<-'
        $localBranch = $row[0].Trim()
        $remoteBranch = $row[1].Trim()

        $query = "branch.${localBranch}.remote"
        $configRemote = git config --get $query
        if (-not $remoteBranch -and -not $configRemote) {
            $notTrackedLocalBranches += $localBranch
        }
    }

    git branch -r | ForEach-Object {
        $localBranch = $_
        $localBranch = $localBranch.Trim().Replace($remoteRefs, '').Trim()
        $localBranch = $localBranch.Trim().Replace('*', '').Trim()
        $remoteBranch = $_.Trim().Replace('*', '').Trim()

        if ($remoteBranch.StartsWith($remoteRefs + 'HEAD') -or -not ($remoteBranch.StartsWith($remoteRefs))) {
            return
        }

        if (-not ($notTrackedLocalBranches -contains $localBranch) -and -not ($localBranches -contains $localBranch)) {
            git branch -t $localBranch $remoteBranch
        } elseif ($notTrackedLocalBranches -contains $localBranch) {
            git branch -u $remoteBranch $localBranch
        }
    }
}

function Set-GitTrackMatchedRemoteBranches($RemoteRefs) {
    if ($null -eq $RemoteRefs) {
        $RemoteRefs = 'origin/'
    }

    $notTrackedLocalBranches = @()

    git for-each-ref --format='%(refname:short) <- %(upstream:short)' 'refs/heads' | ForEach-Object {
        $row = $_ -split '<-'
        $localBranch = $row[0].Trim()
        $remoteBranch = $row[1].Trim()

        $query = "branch.${localBranch}.remote"
        $configRemote = git config --get $query
        if (-not $remoteBranch -and -not $configRemote) {
            $notTrackedLocalBranches += $localBranch
        }
    }

    $remotes = git branch -r | ForEach-Object { $_.Trim().Replace('*', '').Trim() }

    $notTrackedLocalBranches | ForEach-Object {
        $localBranch = $_
        $remotes | ForEach-Object {
            $remoteBranch = $_
            if ($remoteBranch -eq ($RemoteRefs + $localBranch)) {
                git branch -u $remoteBranch $localBranch
                return
            }
        }
    }
}

function Update-GitAllBranches() {
    $currentBranch = git rev-parse --abbrev-ref HEAD

    git fetch --all

    $branchPairs = git for-each-ref --format='%(refname:short) <- %(upstream:short)' 'refs/heads'
    $branchPairs | ForEach-Object {
        $pair = $_ -split ' <- '
        $localBranch = $pair[0]
        $remoteBranch = $pair[1]
        if ($localBranch -and $remoteBranch) {
            Log info "Processing branch '${localBranch}'..."
            git checkout $localBranch
            git rebase $remoteBranch
        }
    }

    git checkout $currentBranch
}

function Update-GitBranch() {
    git fetch --all

    $localBranch = git rev-parse --abbrev-ref HEAD
    $remoteBranch = git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}'
    if (-not $remoteBranch) {
        Print-Warning "No upstream configured for branch '${localBranch}'"
        return
    }

    $remoteBranches = git for-each-ref --format='%(upstream:short)' 'refs/heads'
    foreach ($branch in $remoteBranches) {
        if ( $branch -eq $remoteBranch) {
            Log info "Rebase branch '${remoteBranch}' into '${localBranch}'..."
            git rebase $remoteBranch
            break
        }
    }
}

function Add-AssumedUnchanged {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    $files = Get-Item $Path | Select-Object -ExpandProperty FullName
    $files | Log info

    $title = 'Add assume-unchanged flag'
    $message = 'Do you want to add the assume-unchanged flag for the files displayed above?'
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Add the assume-unchanged flag for each file at the Git index.'
    $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'Does not make any changes.'
    $options = [System.Management.Automation.Host.ChoiceDescription[]] @($yes, $no)

    $choice = $Host.UI.PromptForChoice($title, $message, $options, 1)
    switch ($choice) {
        0 {
            foreach ($file in $files) {
                git update-index --assume-unchanged -- $file
            }
            Log info 'Add assumed-unchanged.'
        }
        1 { Log info 'Nothing changed.' }
    }
}

function Remove-AssumedUnchanged {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    $files = Get-Item $Path | Select-Object -ExpandProperty FullName
    $files | Log info

    $title = 'Remove assume-unchanged flag'
    $message = 'Do you want to remove the assume-unchanged flag for the files displayed above?'
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Remove the assume-unchanged flag for each file at the Git index.'
    $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'Does not make any changes.'
    $options = [System.Management.Automation.Host.ChoiceDescription[]] @($yes, $no)

    $choice = $Host.UI.PromptForChoice($title, $message, $options, 1)
    switch ($choice) {
        0 {
            foreach ($file in $files) {
                git update-index --no-assume-unchanged -- $file
            }
            Log info 'Removed assumed-unchanged.'
        }
        1 { Log info 'Nothing changed.' }
    }
}

New-Alias agt Add-GitTag
New-Alias cgb Clear-GitBranches
New-Alias gk Invoke-Gitk
New-Alias gka Invoke-GitkAll
New-Alias pgst Push-GitAllTrackedBranches
New-Alias ugab Update-GitAllBranches
New-Alias ugb Update-GitBranch
# SIG # Begin signature block
# MIIcjgYJKoZIhvcNAQcCoIIcfzCCHHsCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAlZW9r3lNhK8UD
# bG5sz8nhRzNtvSIELfI3eJsLb4opkqCCF5gwggUhMIIECaADAgECAhAIWwDz5iwy
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
# CisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAX5XiI
# go0lIra0c8/NgEroJ9z+JRp98nJZf8aiVFVTFzANBgkqhkiG9w0BAQEFAASCAQA5
# QqiyCDPqfywP+wrYr72Bx3yNBlrnKyLpC+MAlCNMN3ya+YMLpmJxDxlW88hJkTgs
# AwWQOUg+/mKDQbTJ76EScC9VJL89Brdq+axhNFdirf1smdoMrE4VjvOxE1Xg+/l/
# d4Ei9Lin9M5Ib1hNoyA3BF06mizy9VYghOblbUg02qHUCiTzg/XpvAVB2Pr88LmH
# /gWdTfKC50MqPvm8mGxm4yIULwqhyOWU2a58jzZ160+BkHLK8gdnNV3loAngscSz
# IU8HEC0cCK43BTUNFRGTf2tMo30Rpld7aGygYfldgXZji0I9L2hfnUjSWV75R0Fe
# 0sumVLwf7gOJB6eoU8x4oYICDzCCAgsGCSqGSIb3DQEJBjGCAfwwggH4AgEBMHYw
# YjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgQXNzdXJlZCBJRCBD
# QS0xAhADAZoCOv9YsWvW1ermF/BmMAkGBSsOAwIaBQCgXTAYBgkqhkiG9w0BCQMx
# CwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yMDAzMDkyMjI2MDNaMCMGCSqG
# SIb3DQEJBDEWBBSi8dciEWd4ni8dj2khY6rqjmoRnTANBgkqhkiG9w0BAQEFAASC
# AQAO/c6GjA9n2NsPsvJs9Sm0tnX4t5MSC7jYFuBapKrfiiXvwmtN1Vfmy+jpArPu
# nZFEL2XWd2tFyPO9FP+ZuNiziJnUz3szRoc2sowPkUuTozbs86qz54HVuRcGBpxN
# E3qOFAu7eus9PrPSOxv/tskXJBQBaGPof4kJ16n7Bra5hP2XBy7OPI9EL/b4a705
# BXDfXv6yAeyaPTn7TFW9dOmABEESD2+c0DfEqpQ7L0XrADF9286OOLdGh51wYqmi
# MJF/bNgMXx0rGvrUKfP5aLwF1L9sekEwnu33Xx9EKh4w37+1qSBqz513HOhMCrmC
# EQs6E6WIZjQm0nYbMoz1d7Bg
# SIG # End signature block
