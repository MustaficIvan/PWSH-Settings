# Dot source all libraries by loading external file
. $PSScriptRoot\Mailozaurr.Libraries.ps1

# Dot source all classes by loading external file
. $PSScriptRoot\Mailozaurr.Classes.ps1

function Remove-EmptyValue { 
    [alias('Remove-EmptyValues')]
    [CmdletBinding()]
    param([alias('Splat', 'IDictionary')][Parameter(Mandatory)][System.Collections.IDictionary] $Hashtable,
        [string[]] $ExcludeParameter,
        [switch] $Recursive,
        [int] $Rerun,
        [switch] $DoNotRemoveNull,
        [switch] $DoNotRemoveEmpty,
        [switch] $DoNotRemoveEmptyArray,
        [switch] $DoNotRemoveEmptyDictionary)
    foreach ($Key in [string[]] $Hashtable.Keys) { if ($Key -notin $ExcludeParameter) { if ($Recursive) { if ($Hashtable[$Key] -is [System.Collections.IDictionary]) { if ($Hashtable[$Key].Count -eq 0) { if (-not $DoNotRemoveEmptyDictionary) { $Hashtable.Remove($Key) } } else { Remove-EmptyValue -Hashtable $Hashtable[$Key] -Recursive:$Recursive } } else { if (-not $DoNotRemoveNull -and $null -eq $Hashtable[$Key]) { $Hashtable.Remove($Key) } elseif (-not $DoNotRemoveEmpty -and $Hashtable[$Key] -is [string] -and $Hashtable[$Key] -eq '') { $Hashtable.Remove($Key) } elseif (-not $DoNotRemoveEmptyArray -and $Hashtable[$Key] -is [System.Collections.IList] -and $Hashtable[$Key].Count -eq 0) { $Hashtable.Remove($Key) } } } else { if (-not $DoNotRemoveNull -and $null -eq $Hashtable[$Key]) { $Hashtable.Remove($Key) } elseif (-not $DoNotRemoveEmpty -and $Hashtable[$Key] -is [string] -and $Hashtable[$Key] -eq '') { $Hashtable.Remove($Key) } elseif (-not $DoNotRemoveEmptyArray -and $Hashtable[$Key] -is [System.Collections.IList] -and $Hashtable[$Key].Count -eq 0) { $Hashtable.Remove($Key) } } } }
    if ($Rerun) { for ($i = 0; $i -lt $Rerun; $i++) { Remove-EmptyValue -Hashtable $Hashtable -Recursive:$Recursive } }
}
function Connect-O365Graph {
    [cmdletBinding()]
    param(
        [string][alias('ClientID')] $ApplicationID,
        [string][alias('ClientSecret')] $ApplicationKey,
        [string] $TenantDomain,
        [ValidateSet('https://manage.office.com', 'https://graph.microsoft.com')] $Resource = 'https://manage.office.com'
    )
    # https://dzone.com/articles/getting-access-token-for-microsoft-graph-using-oau-1

    #$Scope = @(
    #'https://outlook.office.com/IMAP.AccessAsUser.All',
    # 'https://outlook.office.com/POP.AccessAsUser.All',
    #    'https://outlook.office.com/Mail.Send'
    #    'https://outlook.office.com/User.Read'
    #)

    $Body = @{
        grant_type    = 'client_credentials'
        resource      = $Resource
        client_id     = $ApplicationID
        client_secret = $ApplicationKey
        #scope         = [System.Web.HttpUtility]::UrlEncode( $Scope)
    }
    try {
        $Authorization = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$($TenantDomain)/oauth2/token" -Body $body -ErrorAction Stop
    } catch {
        $ErrorMessage = $_.Exception.Message -replace "`n", ' ' -replace "`r", ' '
        Write-Warning -Message "Connect-O365Graph - Error: $ErrorMessage"
    }
    if ($Authorization) {
        @{'Authorization' = "$($Authorization.token_type) $($Authorization.access_token)" }
    } else {
        $null
    }
}
function Connect-O365GraphMSAL {
    [cmdletBinding()]
    param(
        [string][alias('ClientSecret')] $ApplicationKey
    )
    @{'Authorization' = "Bearer $ApplicationKey" }
}
function ConvertFrom-GraphCredential {
    [cmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCredential] $Credential
    )
    if ($Credential.UserName -eq 'MSAL') {
        [PSCustomObject] @{
            ClientID     = 'MSAL'
            ClientSecret = $Credential.GetNetworkCredential().Password
        }
    } else {
        $Object = $Credential.UserName -split '@'
        if ($Object.Count -eq 2) {
            [PSCustomObject] @{
                ClientID     = $Object[0]
                DirectoryID  = $Object[1]
                ClientSecret = $Credential.GetNetworkCredential().Password
            }
        }
    }
}
function ConvertFrom-OAuth2Credential {
    [cmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCredential] $Credential
    )
    [PSCustomObject] @{
        UserName = $Credential.UserName
        Token    = $Credential.GetNetworkCredential().Password
    }
}
function ConvertTo-GraphAddress {
    [cmdletBinding()]
    param(
        [Array] $MailboxAddress,
        [object] $From,
        [switch] $LimitedFrom
    )
    foreach ($_ in $MailboxAddress) {
        if ($_ -is [string]) {
            if ($_) {
                @{
                    emailAddress = @{
                        address = $_
                    }
                }
            }
        } elseif ($_ -is [System.Collections.IDictionary]) {
            if ($_.Email) {
                @{
                    emailAddress = @{
                        address = $_.Email
                    }
                }
            }
        } elseif ($_ -is [MimeKit.MailboxAddress]) {
            if ($_.Address) {
                @{
                    emailAddress = @{
                        address = $_.Address
                    }
                }
            }
        } else {
            if ($_.Name -and $_.Email) {
                @{
                    emailAddress = @{
                        address = $_.Email
                    }
                }
            } elseif ($_.Email) {
                @{
                    emailAddress = @{
                        address = $_.Email
                    }
                }

            }
        }
    }
    if ($From) {
        if ($From -is [string]) {
            if ($LimitedFrom) {
                $From
            } else {
                @{
                    emailAddress = @{
                        address = $From
                    }
                }
            }
        } elseif ($From -is [System.Collections.IDictionary]) {
            if ($LimitedFrom) {
                $From.Email
            } else {
                @{
                    emailAddress = @{
                        address = $From.Name
                        #name    = $From.Name
                    }
                }
            }
        }
    }
}
function ConvertTo-MailboxAddress {
    [cmdletBinding()]
    param(
        [Array] $MailboxAddress
    )
    <#
    MimeKit.MailboxAddress new(System.Text.Encoding encoding, string name, System.Collections.Generic.IEnumerable[string] route, string address)
    MimeKit.MailboxAddress new(string name, System.Collections.Generic.IEnumerable[string] route, string address)
    MimeKit.MailboxAddress new(System.Collections.Generic.IEnumerable[string] route, string address)
    MimeKit.MailboxAddress new(System.Text.Encoding encoding, string name, string address)
    MimeKit.MailboxAddress new(string name, string address)
    MimeKit.MailboxAddress new(string address)
    #>
    foreach ($_ in $MailboxAddress) {
        if ($_ -is [string]) {
            $SmtpTo = [MimeKit.MailboxAddress]::new("$_")
        } elseif ($_ -is [System.Collections.IDictionary]) {
            $SmtpTo = [MimeKit.MailboxAddress]::new($_.Name, $_.Email)
        } elseif ($_ -is [MimeKit.MailboxAddress]) {
            $SmtpTo = $_
        } else {
            if ($_.Name -and $_.Email) {
                $SmtpTo = [MimeKit.MailboxAddress]::new($_.Name, $_.Email)
            } elseif ($_.Email) {
                $SmtpTo = [MimeKit.MailboxAddress]::new($_.Email)
            }
        }
        $SmtpTo
    }
}
function ConvertTo-SendGridAddress {
    [cmdletBinding()]
    param(
        [Array] $MailboxAddress,
        [alias('ReplyTo')][object] $From,
        [switch] $LimitedFrom
    )
    foreach ($_ in $MailboxAddress) {
        if ($_ -is [string]) {
            if ($_) {
                @{ email = $_ }
            }
        } elseif ($_ -is [System.Collections.IDictionary]) {
            if ($_.Email) {
                @{ email = $_.Email }
            }
        } elseif ($_ -is [MimeKit.MailboxAddress]) {
            if ($_.Address) {
                @{ email = $_.Address }
            }
        } else {
            if ($_.Name -and $_.Email) {
                @{
                    email = $_.Email
                    name  = $_.Name
                }
            } elseif ($_.Email) {
                @{ email = $_.Email }
            }
        }
    }
    if ($From) {
        if ($From -is [string]) {
            if ($LimitedFrom) {
                $From
            } else {
                @{ email = $From }
            }
        } elseif ($From -is [System.Collections.IDictionary]) {
            if ($LimitedFrom) {
                $From.Email
            } else {
                @{
                    email = $From.Email
                    name  = $From.Name
                }
            }
        }
    }
}
function Invoke-O365Graph {
    [cmdletBinding()]
    param(
        [uri] $PrimaryUri = 'https://graph.microsoft.com/v1.0',
        [uri] $Uri,
        [alias('Authorization')][System.Collections.IDictionary] $Headers,
        [validateset('GET', 'DELETE', 'POST')][string] $Method = 'GET',
        [string] $ContentType = 'application/json',
        [switch] $FullUri
    )
    $RestSplat = @{
        Headers     = $Headers
        Method      = $Method
        ContentType = $ContentType
    }
    if ($FullUri) {
        $RestSplat.Uri = $Uri
    } else {
        $RestSplat.Uri = -join ($PrimaryUri, $Uri)
    }
    try {
        $OutputQuery = Invoke-RestMethod @RestSplat -Verbose:$false
        if ($Method -eq 'GET') {
            if ($OutputQuery.value) {
                $OutputQuery.value
            }
            if ($OutputQuery.'@odata.nextLink') {
                $RestSplat.Uri = $OutputQuery.'@odata.nextLink'
                $MoreData = Invoke-O365Graph @RestSplat -FullUri
                if ($MoreData) {
                    $MoreData
                }
            }
        } else {
            return $true
        }
    } catch {
        $RestError = $_.ErrorDetails.Message
        if ($RestError) {
            try {
                $ErrorMessage = ConvertFrom-Json -InputObject $RestError
                $ErrorMy = -join ('JSON Error:' , $ErrorMessage.error.code, ' ', $ErrorMessage.error.message, ' Additional Error: ', $_.Exception.Message)
                Write-Warning $ErrorMy
            } catch {
                Write-Warning $_.Exception.Message
            }
        } else {
            Write-Warning $_.Exception.Message
        }
        if ($Method -ne 'GET') {
            return $false
        }
    }
}
[string[]] $Script:BlockList = @(
    'b.barracudacentral.org'
    'spam.rbl.msrbl.net'
    'zen.spamhaus.org'
    'bl.deadbeef.com'
    #'bl.emailbasura.org' dead as per https://github.com/EvotecIT/PSBlackListChecker/issues/8
    'bl.spamcop.net'
    'blackholes.five-ten-sg.com'
    'blacklist.woody.ch'
    'bogons.cymru.com'
    'cbl.abuseat.org'
    'combined.abuse.ch'
    'combined.rbl.msrbl.net'
    'db.wpbl.info'
    'dnsbl-1.uceprotect.net'
    'dnsbl-2.uceprotect.net'
    'dnsbl-3.uceprotect.net'
    'dnsbl.cyberlogic.net'
    'dnsbl.inps.de'
    'dnsbl.sorbs.net'
    'drone.abuse.ch'
    'drone.abuse.ch'
    'duinv.aupads.org'
    'dul.dnsbl.sorbs.net'
    'dul.ru'
    'dyna.spamrats.com'
    # 'dynip.rothen.com' dead as per https://github.com/EvotecIT/PSBlackListChecker/issues/9
    'http.dnsbl.sorbs.net'
    'images.rbl.msrbl.net'
    'ips.backscatterer.org'
    'ix.dnsbl.manitu.net'
    'korea.services.net'
    'misc.dnsbl.sorbs.net'
    'noptr.spamrats.com'
    'ohps.dnsbl.net.au'
    'omrs.dnsbl.net.au'
    'orvedb.aupads.org'
    'osps.dnsbl.net.au'
    'osrs.dnsbl.net.au'
    'owfs.dnsbl.net.au'
    'owps.dnsbl.net.au'
    'pbl.spamhaus.org'
    'phishing.rbl.msrbl.net'
    'probes.dnsbl.net.au'
    'proxy.bl.gweep.ca'
    'proxy.block.transip.nl'
    'psbl.surriel.com'
    'rbl.interserver.net'
    'rdts.dnsbl.net.au'
    'relays.bl.gweep.ca'
    'relays.bl.kundenserver.de'
    'relays.nether.net'
    'residential.block.transip.nl'
    'ricn.dnsbl.net.au'
    'rmst.dnsbl.net.au'
    'sbl.spamhaus.org'
    'short.rbl.jp'
    'smtp.dnsbl.sorbs.net'
    'socks.dnsbl.sorbs.net'
    'spam.abuse.ch'
    'spam.dnsbl.sorbs.net'
    'spam.spamrats.com'
    'spamlist.or.kr'
    'spamrbl.imp.ch'
    't3direct.dnsbl.net.au'
    'ubl.lashback.com'
    'ubl.unsubscore.com'
    'virbl.bit.nl'
    'virus.rbl.jp'
    'virus.rbl.msrbl.net'
    'web.dnsbl.sorbs.net'
    'wormrbl.imp.ch'
    'xbl.spamhaus.org'
    'zombie.dnsbl.sorbs.net'
    #'bl.spamcannibal.org' now a parked domain
    #'tor.ahbl.org' # as per https://ahbl.org/ was terminated in 2015
    #'tor.dnsbl.sectoor.de' parked domain
    #'torserver.tor.dnsbl.sectoor.de' as above
    #'dnsbl.njabl.org' # supposedly doesn't work properly anymore
    # 'dnsbl.ahbl.org' # as per https://ahbl.org/ was terminated in 2015
    # 'cdl.anti-spam.org.cn' Inactive
)
$Script:DNSTypes = @{
    A          = '1'
    NS         = '2'
    MD         = '3'
    MF         = '4'
    CNAME      = '5'
    SOA        = '6'
    MB         = '7'
    MG         = '8'
    MR         = '9'
    NULL       = '10'
    WKS        = '11'
    PTR        = '12'
    HINFO      = '13'
    MINFO      = '14'
    MX         = '15'
    TXT        = '16'
    RP         = '17'
    AFSDB      = '18'
    X25        = '19'
    ISDN       = '20'
    RT         = '21'
    NSAP       = '22'
    NSAPPTR    = '23'
    SIG        = '24'
    KEY        = '25'
    PX         = '26'
    GPOS       = '27'
    AAAA       = '28'
    LOC        = '29'
    NXT        = '30'
    EID        = '31'
    NIMLOC     = '32'
    SRV        = '33'
    ATMA       = '34'
    NAPTR      = '35'
    KX         = '36'
    CERT       = '37'
    A6         = '38'
    DNAME      = '39'
    SINK       = '40'
    OPT        = '41'
    APL        = '42'
    DS         = '43'
    SSHFP      = '44'
    IPSECKEY   = '45'
    RRSIG      = '46'
    NSEC       = '47'
    DNSKEY     = '48'
    DHCID      = '49'
    NSEC3      = '50'
    NSEC3PARAM = '51'
    TLSA       = '52'
    SMIMEA     = '53'
    Unassigned = '54'
    HIP        = '55'
    NINFO      = '56'
    RKEY       = '57'
    TALINK     = '58'
    CDS        = '59'
    CDNSKEY    = '60'
    OPENPGPKEY = '61'
    CSYNC      = '62'
    SPF        = '99'
    UINFO      = '100'
    UID        = '101'
    GID        = '102'
    UNSPEC     = '103'
    NID        = '104'
    L32        = '105'
    L64        = '106'
    LP         = '107'
    EUI48      = '108'
    EUI64      = '109'
    TKEY       = '249'
    TSIG       = '250'
    IXFR       = '251'
    AXFR       = '252'
    MAILB      = '253'
    MAILA      = '254'
    All        = '255'
    URI        = '256'
    CAA        = '257'
    AVC        = '258'
    DOA        = '259'
    TA         = '32768'
    DLV        = '32769'
}

$Script:DNSQueryTypes = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    $Script:DNSTypes.Keys | Where-Object { $_ -like "*$wordToComplete*" }
}
function Send-GraphMailMessage {
    [cmdletBinding(SupportsShouldProcess)]
    param(
        [object] $From,
        [Array] $To,
        [Array] $Cc,
        [Array] $Bcc,
        [string] $ReplyTo,
        [string] $Subject,
        [alias('Body')][string[]] $HTML,
        [string[]] $Text,
        [alias('Attachments')][string[]] $Attachment,
        [PSCredential] $Credential,
        [alias('Importance')][ValidateSet('Low', 'Normal', 'High')][string] $Priority,
        [switch] $DoNotSaveToSentItems
    )
    if ($Credential) {
        $AuthorizationData = ConvertFrom-GraphCredential -Credential $Credential
    } else {
        return
    }
    if ($AuthorizationData.ClientID -eq 'MSAL') {
        $Authorization = Connect-O365GraphMSAL -ApplicationKey $AuthorizationData.ClientSecret
    } else {
        $Authorization = Connect-O365Graph -ApplicationID $AuthorizationData.ClientID -ApplicationKey $AuthorizationData.ClientSecret -TenantDomain $AuthorizationData.DirectoryID -Resource https://graph.microsoft.com
    }
    $Body = @{}
    if ($HTML) {
        $Body['contentType'] = 'HTML'
        $body['content'] = $HTML -join [System.Environment]::NewLine
    } elseif ($Text) {
        $Body['contentType'] = 'Text'
        $body['content'] = $Text -join [System.Environment]::NewLine
    } else {
        $Body['contentType'] = 'Text'
        $body['content'] = ''
    }

    $Message = [ordered] @{
        # https://docs.microsoft.com/en-us/graph/api/resources/message?view=graph-rest-1.0
        message         = [ordered] @{
            subject       = $Subject
            body          = $Body
            from          = ConvertTo-GraphAddress -From $From
            toRecipients  = @(
                ConvertTo-GraphAddress -MailboxAddress $To
            )
            ccRecipients  = @(
                ConvertTo-GraphAddress -MailboxAddress $CC
            )
            bccRecipients = @(
                ConvertTo-GraphAddress -MailboxAddress $BCC
            )
            #sender                 = @(
            #    ConvertTo-GraphAddress -MailboxAddress $From
            #)
            replyTo       = @(
                ConvertTo-GraphAddress -MailboxAddress $ReplyTo
            )
            attachments   = @(
                foreach ($A in $Attachment) {
                    $ItemInformation = Get-Item -Path $A
                    if ($ItemInformation) {
                        $File = [system.io.file]::ReadAllBytes($A)
                        $Bytes = [System.Convert]::ToBase64String($File)
                        @{
                            '@odata.type'  = '#microsoft.graph.fileAttachment'
                            'name'         = $ItemInformation.Name
                            #'contentType'  = 'text/plain'
                            'contentBytes' = $Bytes
                        }
                    }
                }
            )
            importance    = $Priority
            #isReadReceiptRequested     = $true
            #isDeliveryReceiptRequested = $true
        }
        saveToSentItems = -not $DoNotSaveToSentItems.IsPresent
    }
    $MailSentTo = -join ($To -join ',', $CC -join ', ', $Bcc -join ', ')
    Remove-EmptyValue -Hashtable $Message -Recursive -Rerun 2
    $Body = $Message | ConvertTo-Json -Depth 5
    $FromField = ConvertTo-GraphAddress -From $From -LimitedFrom
    Try {
        if ($PSCmdlet.ShouldProcess("$MailSentTo", 'Send-EmailMessage')) {
            $null = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$FromField/sendMail" -Headers $Authorization -Method POST -Body $Body -ContentType 'application/json; charset=UTF-8' -ErrorAction Stop
            if (-not $Suppress) {
                [PSCustomObject] @{
                    Status   = $True
                    Error    = ''
                    SentTo   = $MailSentTo
                    SentFrom = $FromField
                }
            }
        } else {
            if (-not $Suppress) {
                [PSCustomObject] @{
                    Status = $false
                    Error  = 'Email not sent (WhatIf)'
                    SentTo = $MailSentTo
                }
            }
        }
    } catch {
        if ($PSBoundParameters.ErrorAction -eq 'Stop') {
            Write-Error $_
            return
        }
        $RestError = $_.ErrorDetails.Message
        $RestMessage = $_.Exception.Message
        if ($RestError) {
            try {
                $ErrorMessage = ConvertFrom-Json -InputObject $RestError -ErrorAction Stop
                $ErrorText = $ErrorMessage.error.message
                # Write-Warning -Message "Invoke-Graph - [$($ErrorMessage.error.code)] $($ErrorMessage.error.message), exception: $($_.Exception.Message)"
                Write-Warning -Message "Send-GraphMailMessage - Error: $($RestMessage) $($ErrorText)"
            } catch {
                $ErrorText = ''
                Write-Warning -Message "Send-GraphMailMessage - Error: $($RestMessage)"
            }
        } else {
            Write-Warning -Message "Send-GraphMailMessage - Error: $($_.Exception.Message)"
        }
        if ($_.ErrorDetails.RecommendedAction) {
            Write-Warning -Message "Send-GraphMailMessage - Recommended action: $RecommendedAction"
        }
        if (-not $Suppress) {
            [PSCustomObject] @{
                Status   = $False
                Error    = if ($RestError) { "$($RestMessage) $($ErrorText)" }  else { $RestMessage }
                SentTo   = $MailSentTo
                SentFrom = $FromField
            }
        }
    }
    if ($VerbosePreference) {
        if ($Message.message.attachments) {
            $Message.message.attachments | ForEach-Object {
                if ($_.contentBytes.Length -ge 10) {
                    $_.contentBytes = -join ($_.contentBytes.Substring(0, 10), 'ContentIsTrimmed')
                } else {
                    $_.contentBytes = -join ($_.contentBytes, 'ContentIsTrimmed')
                }

            }
        }
        If ($Message.message.body.content) {
            if ($Message.message.body.content.Length -gt 10) {
                $Message.message.body.content = -join ($Message.message.body.content.Substring(0, 10), 'ContentIsTrimmed')
            } else {
                $Message.message.body.content = -join ($Message.message.body.content, 'ContentIsTrimmed')
            }

        }
        $TrimmedBody = $Message | ConvertTo-Json -Depth 5
        Write-Verbose "Message content: $TrimmedBody"
    }
}
function Send-SendGridMailMessage {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [object] $From,
        [Array] $To,
        [Array] $Cc,
        [Array] $Bcc,
        [string] $ReplyTo,
        [string] $Subject,
        [alias('Body')][string[]] $HTML,
        [string[]] $Text,
        [alias('Attachments')][string[]] $Attachment,
        [PSCredential] $Credential,
        [alias('Importance')][ValidateSet('Low', 'Normal', 'High')][string] $Priority,
        [switch] $SeparateTo
    )
    # https://sendgrid.api-docs.io/v3.0/mail-send/v3-mail-send
    if ($Credential) {
        $AuthorizationData = ConvertFrom-OAuth2Credential -Credential $Credential
    } else {
        return
    }
    $SendGridMessage = [ordered]@{
        personalizations = [System.Collections.Generic.List[object]]::new()
        from             = ConvertTo-SendGridAddress -From $From
        content          = @(
            @{
                type  = if ($HTML) { 'text/html' } else { 'text/plain' }
                value = if ($HTML) { $HTML } else { $Text }
            }
        )
        attachments      = @(
            foreach ($A in $Attachment) {
                $ItemInformation = Get-Item -Path $A
                if ($ItemInformation) {
                    $File = [system.io.file]::ReadAllBytes($A)
                    $Bytes = [System.Convert]::ToBase64String($File)
                    @{
                        'filename'    = $ItemInformation.Name
                        #'type'  = 'text/plain'
                        'content'     = $Bytes
                        'disposition' = 'attachment' # inline or attachment
                    }
                }
            }
        )
        #send_at          = [Math]::Floor([decimal](Get-Date(Get-Date).ToUniversalTime()-UFormat "%s"))
    }

    if ($ReplyTo) {
        $SendGridMessage["reply_to"] = ConvertTo-SendGridAddress -ReplyTo $ReplyTo
    }
    if ($Subject.Length -le 1) {
        # Subject must be at least char in lenght
        $Subject = ' '
    }

    [Array] $SendGridTo = ConvertTo-SendGridAddress -MailboxAddress $To
    [Array] $SendGridCC = ConvertTo-SendGridAddress -MailboxAddress $CC
    [Array] $SendGridBCC = ConvertTo-SendGridAddress -MailboxAddress $Bcc

    if ($SeparateTo) {
        if ($CC -or $BCC) {
            Write-Warning "Send-EmailMessage - Using SeparateTo parameter where there are multiple recipients for TO and CC or BCC is not supported by SendGrid."
            Write-Warning "Send-EmailMessage - SendGrid requires unique email addresses to be available as part of all recipient fields."
            Write-Warning "Send-EmailMessage - Please use SeparateTo parameter only with TO field. Skipping CC/BCC."
        }
        foreach ($T in $To) {
            $Personalization = @{
                subject = $Subject
                to      = @(
                    ConvertTo-SendGridAddress -MailboxAddress $T
                )
            }
            Remove-EmptyValue -Hashtable $Personalization -Recursive
            $SendGridMessage.personalizations.Add($Personalization)
        }
    } else {
        $Personalization = [ordered] @{
            cc      = $SendGridCC
            bcc     = $SendGridBCC
            to      = $SendGridTo
            subject = $Subject
        }
        Remove-EmptyValue -Hashtable $Personalization -Recursive
        $SendGridMessage.personalizations.Add($Personalization)
    }

    Remove-EmptyValue -Hashtable $SendGridMessage -Recursive -Rerun 2

    $InvokeRestMethodParams = [ordered] @{
        URI         = 'https://api.sendgrid.com/v3/mail/send'
        Headers     = @{'Authorization' = "Bearer $($AuthorizationData.Token)" }
        Method      = 'POST'
        Body        = $SendGridMessage | ConvertTo-Json -Depth 5
        ErrorAction = 'Stop'
        ContentType = 'application/json; charset=utf-8'
    }

    [Array] $MailSentTo = ($SendGridTo.Email, $SendGridCC.Email, $SendGridBCC.Email) | ForEach-Object { if ($_) { $_ } }
    [string] $MailSentList = $MailSentTo -join ','
    try {
        if ($PSCmdlet.ShouldProcess("$MailSentList", 'Send-EmailMessage')) {
            $null = Invoke-RestMethod @InvokeRestMethodParams
            if (-not $Suppress) {
                [PSCustomObject] @{
                    Status   = $True
                    Error    = ''
                    SentTo   = $MailSentList
                    SentFrom = $SendGridMessage.From.Email
                }
            }
        }
    } catch {
        # This tries to help user with some assesment
        if ($MailSentTo.Count -gt ($MailSentTo | Sort-Object -Unique).Count) {
            $ErrorDetails = ' Addresses in TO/CC/BCC fields must be unique across all fields which may be reason for a failure.'
        } else {
            $ErrorDetails = ''
        }
        # And here we process error
        if ($PSBoundParameters.ErrorAction -eq 'Stop') {
            Write-Error $_
        } else {
            Write-Warning "Send-EmailMessage - Error: $($_.Exception.Message) $ErrorDetails"
        }
        if (-not $Suppress) {
            [PSCustomObject] @{
                Status   = $False
                Error    = -join ( $($_.Exception.Message), $ErrorDetails)
                SentTo   = $MailSentTo
                SentFrom = $SendGridMessage.From.Email
            }
        }
    }
    # This is to make sure data doesn't flood with attachments content
    if ($VerbosePreference) {
        # Trims attachments content
        if ($SendGridMessage.attachments) {
            $SendGridMessage.attachments | ForEach-Object {
                if ($_.content.Length -ge 10) {
                    $_.content = -join ($_.content.Substring(0, 10), 'ContentIsTrimmed')
                } else {
                    $_.content = -join ($_.content, 'ContentIsTrimmed')
                }

            }
        }
        # Trims body content
        If ($SendGridMessage.content.value) {
            if ($SendGridMessage.content[0].value.Length -gt 10) {
                $SendGridMessage.content[0].value = -join ($SendGridMessage.content[0].value.Substring(0, 10), 'ContentIsTrimmed')
            } else {
                $SendGridMessage.content[0].value = -join ($SendGridMessage.content[0].value, 'ContentIsTrimmed')
            }

        }
        $TrimmedBody = $SendGridMessage | ConvertTo-Json -Depth 5
        Write-Verbose "Message content: $TrimmedBody"
    }
}
function Wait-Task {
    # await replacement
    param (
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)] $Task
    )
    # https://stackoverflow.com/questions/51218257/await-async-c-sharp-method-from-powershell
    process {
        while (-not $Task.AsyncWaitHandle.WaitOne(200)) { }
        $Task.GetAwaiter().GetResult()
    }
}
function Connect-IMAP {
    [cmdletBinding(DefaultParameterSetName = 'Credential')]
    param(
        [Parameter(ParameterSetName = 'oAuth2')]
        [Parameter(ParameterSetName = 'Credential')]
        [Parameter(ParameterSetName = 'ClearText')]
        [Parameter(Mandatory)][string] $Server,

        [Parameter(ParameterSetName = 'oAuth2')]
        [Parameter(ParameterSetName = 'Credential')]
        [Parameter(ParameterSetName = 'ClearText')]
        [int] $Port = '993',

        [Parameter(ParameterSetName = 'ClearText', Mandatory)][string] $UserName,
        [Parameter(ParameterSetName = 'ClearText', Mandatory)][string] $Password,

        [Parameter(ParameterSetName = 'oAuth2')]
        [Parameter(ParameterSetName = 'Credential')][System.Management.Automation.PSCredential] $Credential,

        [Parameter(ParameterSetName = 'oAuth2')]
        [Parameter(ParameterSetName = 'Credential')]
        [Parameter(ParameterSetName = 'ClearText')]
        [MailKit.Security.SecureSocketOptions] $Options = [MailKit.Security.SecureSocketOptions]::Auto,

        [Parameter(ParameterSetName = 'oAuth2')]
        [Parameter(ParameterSetName = 'Credential')]
        [Parameter(ParameterSetName = 'ClearText')]
        [int] $TimeOut = 120000,

        [Parameter(ParameterSetName = 'oAuth2')]
        [switch] $oAuth2
    )
    $Client = [MailKit.Net.Imap.ImapClient]::new()
    try {
        $Client.Connect($Server, $Port, $Options)
    } catch {
        Write-Warning "Connect-IMAP - Unable to connect $($_.Exception.Message)"
        return
    }

    <#
    void Connect(string host, int port, MailKit.Security.SecureSocketOptions options, System.Threading.CancellationToken cancellationToken)
    void Connect(System.Net.Sockets.Socket socket, string host, int port, MailKit.Security.SecureSocketOptions options, System.Threading.CancellationToken cancellationToken)
    void Connect(System.IO.Stream stream, string host, int port, MailKit.Security.SecureSocketOptions options, System.Threading.CancellationToken cancellationToken)
    void Connect(uri uri, System.Threading.CancellationToken cancellationToken)
    void Connect(string host, int port, bool useSsl, System.Threading.CancellationToken cancellationToken)
    void IMailService.Connect(string host, int port, bool useSsl, System.Threading.CancellationToken cancellationToken)
    void IMailService.Connect(string host, int port, MailKit.Security.SecureSocketOptions options, System.Threading.CancellationToken cancellationToken)
    void IMailService.Connect(System.Net.Sockets.Socket socket, string host, int port, MailKit.Security.SecureSocketOptions options, System.Threading.CancellationToken cancellationToken)
    void IMailService.Connect(System.IO.Stream stream, string host, int port, MailKit.Security.SecureSocketOptions options, System.Threading.CancellationToken cancellationToken)
    #>
    if ($Client.TimeOut -ne $TimeOut) {
        $Client.TimeOut = $Timeout
    }
    if ($Client.IsConnected) {
        if ($oAuth2.IsPresent) {
            $Authorization = ConvertFrom-OAuth2Credential -Credential $Credential
            $SaslMechanismOAuth2 = [MailKit.Security.SaslMechanismOAuth2]::new($Authorization.UserName, $Authorization.Token)
            try {
                $Client.Authenticate($SaslMechanismOAuth2)
            } catch {
                Write-Warning "Connect-POP - Unable to authenticate via oAuth $($_.Exception.Message)"
                return
            }
        } elseif ($UserName -and $Password) {
            try {
                $Client.Authenticate($UserName, $Password)
            } catch {
                Write-Warning "Connect-IMAP - Unable to authenticate $($_.Exception.Message)"
                return
            }
        } else {
            try {
                $Client.Authenticate($Credential)
            } catch {
                Write-Warning "Connect-IMAP - Unable to authenticate $($_.Exception.Message)"
                return
            }
        }
    } else {
        return
    }
    if ($Client.IsAuthenticated) {
        [ordered] @{
            Uri                      = $Client.SyncRoot.Uri                      #: pops: / / pop.gmail.com:995 /
            AuthenticationMechanisms = $Client.SyncRoot.AuthenticationMechanisms #: { }
            Capabilities             = $Client.SyncRoot.Capabilities             #: Expire, LoginDelay, Pipelining, ResponseCodes, Top, UIDL, User
            Stream                   = $Client.SyncRoot.Stream                   #: MailKit.Net.Pop3.Pop3Stream
            State                    = $Client.SyncRoot.State                    #: Transaction
            IsConnected              = $Client.SyncRoot.IsConnected              #: True
            ApopToken                = $Client.SyncRoot.ApopToken                #:
            ExpirePolicy             = $Client.SyncRoot.ExpirePolicy             #: 0
            Implementation           = $Client.SyncRoot.Implementation           #:
            LoginDelay               = $Client.SyncRoot.LoginDelay               #: 300
            IsAuthenticated          = $Client.IsAuthenticated
            IsSecure                 = $Client.IsSecure
            Data                     = $Client
            Count                    = $Client.Count
        }
    }
    <#
    void Authenticate(MailKit.Security.SaslMechanism mechanism, System.Threading.CancellationToken cancellationToken)
    void Authenticate(System.Text.Encoding encoding, System.Net.ICredentials credentials, System.Threading.CancellationToken cancellationToken)
    void Authenticate(System.Net.ICredentials credentials, System.Threading.CancellationToken cancellationToken)
    void Authenticate(System.Text.Encoding encoding, string userName, string password, System.Threading.CancellationToken cancellationToken)
    void Authenticate(string userName, string password, System.Threading.CancellationToken cancellationToken)
    void IMailService.Authenticate(System.Net.ICredentials credentials, System.Threading.CancellationToken cancellationToken)
    void IMailService.Authenticate(System.Text.Encoding encoding, System.Net.ICredentials credentials, System.Threading.CancellationToken cancellationToken)
    void IMailService.Authenticate(System.Text.Encoding encoding, string userName, string password, System.Threading.CancellationToken cancellationToken)
    void IMailService.Authenticate(string userName, string password, System.Threading.CancellationToken cancellationToken)
    void IMailService.Authenticate(MailKit.Security.SaslMechanism mechanism, System.Threading.CancellationToken cancellationToken)
    #>

    <#
    -------------------
    System.Threading.Tasks.Task AuthenticateAsync(MailKit.Security.SaslMechanism mechanism, System.Threading.CancellationToken cancellationToken)
    System.Threading.Tasks.Task AuthenticateAsync(System.Text.Encoding encoding, System.Net.ICredentials credentials, System.Threading.CancellationToken cancellati
    onToken)
    System.Threading.Tasks.Task AuthenticateAsync(System.Net.ICredentials credentials, System.Threading.CancellationToken cancellationToken)
    System.Threading.Tasks.Task AuthenticateAsync(System.Text.Encoding encoding, string userName, string password, System.Threading.CancellationToken cancellationT
    oken)
    System.Threading.Tasks.Task AuthenticateAsync(string userName, string password, System.Threading.CancellationToken cancellationToken)
    System.Threading.Tasks.Task IMailService.AuthenticateAsync(System.Net.ICredentials credentials, System.Threading.CancellationToken cancellationToken)
    System.Threading.Tasks.Task IMailService.AuthenticateAsync(System.Text.Encoding encoding, System.Net.ICredentials credentials, System.Threading.CancellationTok
    en cancellationToken)
    System.Threading.Tasks.Task IMailService.AuthenticateAsync(System.Text.Encoding encoding, string userName, string password, System.Threading.CancellationToken
    cancellationToken)
    System.Threading.Tasks.Task IMailService.AuthenticateAsync(string userName, string password, System.Threading.CancellationToken cancellationToken)
    System.Threading.Tasks.Task IMailService.AuthenticateAsync(MailKit.Security.SaslMechanism mechanism, System.Threading.CancellationToken cancellationToken)
    #>

    #$Client.GetMessageSizes
}
function Connect-oAuthGoogle {
    [cmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $GmailAccount,
        [Parameter(Mandatory)][string] $ClientID,
        [Parameter(Mandatory)][string] $ClientSecret,
        [ValidateSet("https://mail.google.com/")][string[]] $Scope = @("https://mail.google.com/")
    )

    $ClientSecrets = [Google.Apis.Auth.OAuth2.ClientSecrets]::new()
    $ClientSecrets.ClientId = $ClientID
    $ClientSecrets.ClientSecret = $ClientSecret

    $Initializer = [Google.Apis.Auth.OAuth2.Flows.GoogleAuthorizationCodeFlow+Initializer]::new()
    $Initializer.DataStore = [Google.Apis.Util.Store.FileDataStore]::new("CredentialCacheFolder", $false)
    $Initializer.Scopes = $Scope
    $Initializer.ClientSecrets = $ClientSecrets

    $CodeFlow = [Google.Apis.Auth.OAuth2.Flows.GoogleAuthorizationCodeFlow]::new($Initializer)

    $codeReceiver = [Google.Apis.Auth.OAuth2.LocalServerCodeReceiver]::new()
    $AuthCode = [Google.Apis.Auth.OAuth2.AuthorizationCodeInstalledApp]::new($CodeFlow, $codeReceiver)
    $Credential = $AuthCode.AuthorizeAsync($GmailAccount, [System.Threading.CancellationToken]::None) | Wait-Task

    if ($Credential.Token.IsExpired([Google.Apis.Util.SystemClock]::Default)) {
        $credential.RefreshTokenAsync([System.Threading.CancellationToken]::None) | Wait-Task
    }
    #$oAuth2 = [MailKit.Security.SaslMechanismOAuth2]::new($credential.UserId, $credential.Token.AccessToken)
    #$oAuth2
    #[PSCustomObject] @{
    #    UserName = $Credential.UserId
    #    Token    = $Credential.Token.AccessToken
    #}
    ConvertTo-OAuth2Credential -UserName $Credential.UserId -Token $Credential.Token.AccessToken
}

function Connect-oAuthO365 {
    [cmdletBinding()]
    param(
        [string] $Login,
        [Parameter(Mandatory)][string] $ClientID,
        [Parameter(Mandatory)][string] $TenantID,
        [uri] $RedirectUri = 'https://login.microsoftonline.com/common/oauth2/nativeclient',
        [ValidateSet(
            "email",
            "offline_access",
            "https://outlook.office.com/IMAP.AccessAsUser.All",
            "https://outlook.office.com/POP.AccessAsUser.All",
            "https://outlook.office.com/SMTP.Send"
        )][string[]] $Scopes = @(
            "email",
            "offline_access",
            "https://outlook.office.com/IMAP.AccessAsUser.All",
            "https://outlook.office.com/POP.AccessAsUser.All",
            "https://outlook.office.com/SMTP.Send"
        )
    )
    $Options = [Microsoft.Identity.Client.PublicClientApplicationOptions]::new()
    $Options.ClientId = $ClientID
    $Options.TenantId = $TenantID
    $Options.RedirectUri = $RedirectUri

    try {
        $PublicClientApplication = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::CreateWithApplicationOptions($Options).Build()
    } catch {
        if ($PSBoundParameters.ErrorAction -eq 'Stop') {
            Write-Error $_
            return
        } else {
            Write-Warning "Connect-oAuthO365 - Error: $($_.Exception.Message)"
            return
        }
    }

    # https://www.powershellgallery.com/packages/MSAL.PS/4.2.1.1/Content/Get-MsalToken.ps1
    # Here we should implement something for Silent Token
    # $Account = $Account
    # $AuthToken = $PublicClientApplication.AcquireTokenSilent($Scopes, $login).ExecuteAsync([System.Threading.CancellationToken]::None) | Wait-Task
    # $oAuth2 = [MailKit.Security.SaslMechanismOAuth2]::new($AuthToken.Account.Username, $AuthToken.AccessToken)

    # https://docs.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth
    try {
        if ($Login) {
            $AuthToken = $PublicClientApplication.AcquireTokenInteractive($Scopes).ExecuteAsync([System.Threading.CancellationToken]::None) | Wait-Task
        } else {
            $AuthToken = $PublicClientApplication.AcquireTokenInteractive($Scopes).WithLoginHint($Login).ExecuteAsync([System.Threading.CancellationToken]::None) | Wait-Task
        }
        # Here we should save the AuthToken.Account somehow, somewhere
        # $AuthToken.Account | Export-Clixml -Path $Env:USERPROFILE\Desktop\test.xml -Depth 2
        #[PSCustomObject] @{
        #    UserName = $AuthToken.Account.UserName
        #    Token    = $AuthToken.AccessToken
        #}
        ConvertTo-OAuth2Credential -UserName $AuthToken.Account.UserName -Token $AuthToken.AccessToken

        #$oAuth2 = [MailKit.Security.SaslMechanismOAuth2]::new($AuthToken.Account.Username, $AuthToken.AccessToken)
        #$oAuth2
    } catch {
        Write-Warning "Connect-oAuth - $_"
    }
}
function Connect-POP {
    [alias('Connect-POP3')]
    [cmdletBinding()]
    param(
        [Parameter(ParameterSetName = 'oAuth2')]
        [Parameter(ParameterSetName = 'Credential')]
        [Parameter(ParameterSetName = 'ClearText')]
        [Parameter(Mandatory)][string] $Server,

        [Parameter(ParameterSetName = 'oAuth2')]
        [Parameter(ParameterSetName = 'Credential')]
        [Parameter(ParameterSetName = 'ClearText')]
        [int] $Port = '995',

        [Parameter(ParameterSetName = 'ClearText', Mandatory)][string] $UserName,
        [Parameter(ParameterSetName = 'ClearText', Mandatory)][string] $Password,


        [Parameter(ParameterSetName = 'oAuth2', Mandatory)]
        [Parameter(ParameterSetName = 'Credential')][System.Management.Automation.PSCredential] $Credential,

        [Parameter(ParameterSetName = 'oAuth2')]
        [Parameter(ParameterSetName = 'Credential')]
        [Parameter(ParameterSetName = 'ClearText')]
        [MailKit.Security.SecureSocketOptions] $Options = [MailKit.Security.SecureSocketOptions]::Auto,

        [Parameter(ParameterSetName = 'oAuth2')]
        [Parameter(ParameterSetName = 'Credential')]
        [Parameter(ParameterSetName = 'ClearText')]
        [int] $TimeOut = 120000,

        [Parameter(ParameterSetName = 'oAuth2')]
        [switch] $oAuth2
    )
    $Client = [MailKit.Net.Pop3.Pop3Client]::new()
    try {
        $Client.Connect($Server, $Port, $Options)
    } catch {
        Write-Warning "Connect-POP - Unable to connect $($_.Exception.Message)"
        return
    }
    <#
    void Connect(string host, int port, MailKit.Security.SecureSocketOptions options, System.Threading.CancellationToken cancellationToken)
    void Connect(System.Net.Sockets.Socket socket, string host, int port, MailKit.Security.SecureSocketOptions options, System.Threading.CancellationToken cancellationToken)
    void Connect(System.IO.Stream stream, string host, int port, MailKit.Security.SecureSocketOptions options, System.Threading.CancellationToken cancellationToken)
    void Connect(uri uri, System.Threading.CancellationToken cancellationToken)
    void Connect(string host, int port, bool useSsl, System.Threading.CancellationToken cancellationToken)
    void IMailService.Connect(string host, int port, bool useSsl, System.Threading.CancellationToken cancellationToken)
    void IMailService.Connect(string host, int port, MailKit.Security.SecureSocketOptions options, System.Threading.CancellationToken cancellationToken)
    void IMailService.Connect(System.Net.Sockets.Socket socket, string host, int port, MailKit.Security.SecureSocketOptions options, System.Threading.CancellationToken cancellationToken)
    void IMailService.Connect(System.IO.Stream stream, string host, int port, MailKit.Security.SecureSocketOptions options, System.Threading.CancellationToken cancellationToken)
    #>
    if ($Client.TimeOut -ne $TimeOut) {
        $Client.TimeOut = $Timeout
    }
    if ($Client.IsConnected) {
        if ($oAuth2.IsPresent) {
            $Authorization = ConvertFrom-OAuth2Credential -Credential $Credential
            $SaslMechanismOAuth2 = [MailKit.Security.SaslMechanismOAuth2]::new($Authorization.UserName, $Authorization.Token)
            try {
                $Client.Authenticate($SaslMechanismOAuth2)
            } catch {
                Write-Warning "Connect-POP - Unable to authenticate via oAuth $($_.Exception.Message)"
                return
            }
        } elseif ($UserName -and $Password) {
            try {
                $Client.Authenticate($UserName, $Password)
            } catch {
                Write-Warning "Connect-POP - Unable to authenticate via UserName/Password $($_.Exception.Message)"
                return
            }
        } else {
            try {
                $Client.Authenticate($Credential)
            } catch {
                Write-Warning "Connect-POP - Unable to authenticate via Credentials $($_.Exception.Message)"
                return
            }
        }
    } else {
        return
    }
    if ($Client.IsAuthenticated) {
        [ordered] @{
            Uri                      = $Client.SyncRoot.Uri                      #: pops: / / pop.gmail.com:995 /
            AuthenticationMechanisms = $Client.SyncRoot.AuthenticationMechanisms #: { }
            Capabilities             = $Client.SyncRoot.Capabilities             #: Expire, LoginDelay, Pipelining, ResponseCodes, Top, UIDL, User
            Stream                   = $Client.SyncRoot.Stream                   #: MailKit.Net.Pop3.Pop3Stream
            State                    = $Client.SyncRoot.State                    #: Transaction
            IsConnected              = $Client.SyncRoot.IsConnected              #: True
            ApopToken                = $Client.SyncRoot.ApopToken                #:
            ExpirePolicy             = $Client.SyncRoot.ExpirePolicy             #: 0
            Implementation           = $Client.SyncRoot.Implementation           #:
            LoginDelay               = $Client.SyncRoot.LoginDelay               #: 300
            IsAuthenticated          = $Client.IsAuthenticated
            IsSecure                 = $Client.IsSecure
            Data                     = $Client
            Count                    = $Client.Count
        }
    }
    <#
    void Authenticate(MailKit.Security.SaslMechanism mechanism, System.Threading.CancellationToken cancellationToken)
    void Authenticate(System.Text.Encoding encoding, System.Net.ICredentials credentials, System.Threading.CancellationToken cancellationToken)
    void Authenticate(System.Net.ICredentials credentials, System.Threading.CancellationToken cancellationToken)
    void Authenticate(System.Text.Encoding encoding, string userName, string password, System.Threading.CancellationToken cancellationToken)
    void Authenticate(string userName, string password, System.Threading.CancellationToken cancellationToken)
    void IMailService.Authenticate(System.Net.ICredentials credentials, System.Threading.CancellationToken cancellationToken)
    void IMailService.Authenticate(System.Text.Encoding encoding, System.Net.ICredentials credentials, System.Threading.CancellationToken cancellationToken)
    void IMailService.Authenticate(System.Text.Encoding encoding, string userName, string password, System.Threading.CancellationToken cancellationToken)
    void IMailService.Authenticate(string userName, string password, System.Threading.CancellationToken cancellationToken)
    void IMailService.Authenticate(MailKit.Security.SaslMechanism mechanism, System.Threading.CancellationToken cancellationToken)
    #>

    <#
    -------------------
    System.Threading.Tasks.Task AuthenticateAsync(MailKit.Security.SaslMechanism mechanism, System.Threading.CancellationToken cancellationToken)
    System.Threading.Tasks.Task AuthenticateAsync(System.Text.Encoding encoding, System.Net.ICredentials credentials, System.Threading.CancellationToken cancellati
    onToken)
    System.Threading.Tasks.Task AuthenticateAsync(System.Net.ICredentials credentials, System.Threading.CancellationToken cancellationToken)
    System.Threading.Tasks.Task AuthenticateAsync(System.Text.Encoding encoding, string userName, string password, System.Threading.CancellationToken cancellationT
    oken)
    System.Threading.Tasks.Task AuthenticateAsync(string userName, string password, System.Threading.CancellationToken cancellationToken)
    System.Threading.Tasks.Task IMailService.AuthenticateAsync(System.Net.ICredentials credentials, System.Threading.CancellationToken cancellationToken)
    System.Threading.Tasks.Task IMailService.AuthenticateAsync(System.Text.Encoding encoding, System.Net.ICredentials credentials, System.Threading.CancellationTok
    en cancellationToken)
    System.Threading.Tasks.Task IMailService.AuthenticateAsync(System.Text.Encoding encoding, string userName, string password, System.Threading.CancellationToken
    cancellationToken)
    System.Threading.Tasks.Task IMailService.AuthenticateAsync(string userName, string password, System.Threading.CancellationToken cancellationToken)
    System.Threading.Tasks.Task IMailService.AuthenticateAsync(MailKit.Security.SaslMechanism mechanism, System.Threading.CancellationToken cancellationToken)
    #>

    #$Client.GetMessageSizes
}
function ConvertTo-GraphCredential {
    [cmdletBinding(DefaultParameterSetName = 'ClearText')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ClearText')]
        [Parameter(Mandatory, ParameterSetName = 'Encrypted')]
        [string] $ClientID,
        [Parameter(Mandatory, ParameterSetName = 'ClearText')]
        [string] $ClientSecret,
        [Parameter(Mandatory, ParameterSetName = 'Encrypted')]
        [string] $ClientSecretEncrypted,
        [Parameter(Mandatory, ParameterSetName = 'ClearText')]
        [Parameter(Mandatory, ParameterSetName = 'Encrypted')]
        [string] $DirectoryID,
        [Parameter(Mandatory, ParameterSetName = 'MsalToken')][alias('Token')][string] $MsalToken,
        [Parameter(Mandatory, ParameterSetName = 'MsalTokenEncrypted')][alias('TokenEncrypted')][string] $MsalTokenEncrypted
    )
    if ($MsalToken -or $MsalTokenEncrypted) {
        # Convert to SecureString
        Try {
            if ($MsalTokenEncrypted) {
                $EncryptedToken = ConvertTo-SecureString -String $MsalTokenEncrypted -ErrorAction Stop
            } else {
                $EncryptedToken = ConvertTo-SecureString -String $MsalToken -AsPlainText -Force -ErrorAction Stop
            }
        } catch {
            if ($PSBoundParameters.ErrorAction -eq 'Stop') {
                Write-Error $_
                return
            } else {
                Write-Warning "ConvertTo-GraphCredential - Error: $($_.Exception.Message)"
                return
            }
        }
        $UserName = 'MSAL'
        $EncryptedCredentials = [System.Management.Automation.PSCredential]::new($UserName, $EncryptedToken)
        $EncryptedCredentials
    } else {
        # Convert to SecureString
        Try {
            if ($ClientSecretEncrypted) {
                $EncryptedToken = ConvertTo-SecureString -String $ClientSecretEncrypted -ErrorAction Stop
            } else {
                $EncryptedToken = ConvertTo-SecureString -String $ClientSecret -AsPlainText -Force -ErrorAction Stop
            }
        } catch {
            if ($PSBoundParameters.ErrorAction -eq 'Stop') {
                Write-Error $_
                return
            } else {
                Write-Warning "ConvertTo-GraphCredential - Error: $($_.Exception.Message)"
                return
            }
        }
        $UserName = -join ($ClientID, '@', $DirectoryID)
        $EncryptedCredentials = [System.Management.Automation.PSCredential]::new($UserName, $EncryptedToken)
        $EncryptedCredentials
    }
}
function ConvertTo-OAuth2Credential {
    [cmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $UserName,
        [Parameter(Mandatory)][string] $Token
    )
    # Convert to SecureString
    $EncryptedToken = ConvertTo-SecureString -String $Token -AsPlainText -Force
    $EncryptedCredentials = [System.Management.Automation.PSCredential]::new($UserName, $EncryptedToken)
    $EncryptedCredentials
}
function ConvertTo-SendGridCredential {
    [cmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $ApiKey
    )
    # Convert to SecureString
    $EncryptedToken = ConvertTo-SecureString -String $ApiKey -AsPlainText -Force
    $EncryptedCredentials = [System.Management.Automation.PSCredential]::new('SendGrid', $EncryptedToken)
    $EncryptedCredentials
}
function Disconnect-IMAP {
    [cmdletBinding()]
    param(
        [System.Collections.IDictionary] $Client
    )
    if ($Client.Data) {
        try {
            $Client.Data.Disconnect($true)
        } catch {
            Write-Warning "Disconnect-IMAP - Unable to authenticate $($_.Exception.Message)"
            return

        }
    }
}
function Disconnect-POP {
    [alias('Disconnect-POP3')]
    [cmdletBinding()]
    param(
        [System.Collections.IDictionary] $Client
    )
    if ($Client.Data) {
        try {
            $Client.Data.Disconnect($true)
        } catch {
            Write-Warning "Disconnect-POP - Unable to authenticate $($_.Exception.Message)"
            return
        }
    }
}
function Find-DKIMRecord {
    <#
    .SYNOPSIS
    Queries DNS to provide DKIM information

    .DESCRIPTION
    Queries DNS to provide DKIM information

    .PARAMETER DomainName
    Name/DomainName to query for DKIM record

    .PARAMETER Selector
    Selector name. Default: selector1

    .PARAMETER DnsServer
    Allows to choose DNS IP address to ask for DNS query. By default uses system ones.

    .PARAMETER DNSProvider
    Allows to choose DNS Provider that will be used for HTTPS based DNS query (Cloudlare or Google)

    .PARAMETER AsHashTable
    Returns Hashtable instead of PSCustomObject

    .PARAMETER AsObject
    Returns an object rather than string based represantation for name servers (for easier display purposes)

    .EXAMPLE
    # Standard way
    Find-DKIMRecord -DomainName 'evotec.pl', 'evotec.xyz' | Format-Table *

    .EXAMPLE
    # Https way via Cloudflare
    Find-DKIMRecord -DomainName 'evotec.pl', 'evotec.xyz' -DNSProvider Cloudflare | Format-Table *

    .EXAMPLE
    # Https way via Google
    Find-DKIMRecord -DomainName 'evotec.pl', 'evotec.xyz' -Selector 'selector1' -DNSProvider Google | Format-Table *

    .NOTES
    General notes
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ValueFromPipeline, Position = 0)][Array] $DomainName,
        [string] $Selector = 'selector1',
        [string] $DnsServer,
        [ValidateSet('Cloudflare', 'Google')][string] $DNSProvider,
        [switch] $AsHashTable,
        [switch] $AsObject
    )
    process {
        foreach ($Domain in $DomainName) {
            if ($Domain -is [string]) {
                $S = $Selector
                $D = $Domain
            } elseif ($Domain -is [System.Collections.IDictionary]) {
                $S = $Domain.Selector
                $D = $Domain.DomainName
                if (-not $S -and -not $D) {
                    Write-Warning 'Find-DKIMRecord - properties DomainName and Selector are required when passing Array of Hashtables'
                }
            }
            $Splat = @{
                Name        = "$S._domainkey.$D"
                Type        = 'TXT'
                ErrorAction = 'SilentlyContinue'
            }
            if ($DNSProvider) {
                $DNSRecord = Resolve-DnsQueryRest @Splat -All -DNSProvider $DnsProvider
            } else {
                if ($DnsServer) {
                    $Splat['Server'] = $DnsServer
                }
                $DNSRecord = Resolve-DnsQuery @Splat -All
            }
            $DNSRecordAnswers = $DNSRecord.Answers | Where-Object Text -Match 'DKIM1'
            if (-not $AsObject) {
                $MailRecord = [ordered] @{
                    Name        = $D
                    Count       = $DNSRecordAnswers.Text.Count
                    Selector    = "$D`:$S"
                    DKIM        = $DNSRecordAnswers.Text -join '; '
                    QueryServer = $DNSRecord.NameServer
                }
            } else {
                $MailRecord = [ordered] @{
                    Name        = $D
                    Count       = $DNSRecordAnswers.Text.Count
                    Selector    = "$D`:$S"
                    DKIM        = $DNSRecordAnswers.Text -join '; '
                    QueryServer = $DNSRecord.NameServer -join '; '
                }
            }
            if ($AsHashTable) {
                $MailRecord
            } else {
                [PSCustomObject] $MailRecord
            }
        }
    }
}
function Find-DMARCRecord {
    <#
    .SYNOPSIS
    Queries DNS to provide DMARC information

    .DESCRIPTION
    Queries DNS to provide DMARC information

    .PARAMETER DomainName
    Name/DomainName to query for DMARC record

    .PARAMETER DnsServer
    Allows to choose DNS IP address to ask for DNS query. By default uses system ones.

    .PARAMETER DNSProvider
    Allows to choose DNS Provider that will be used for HTTPS based DNS query (Cloudlare or Google)

    .PARAMETER AsHashTable
    Returns Hashtable instead of PSCustomObject

    .PARAMETER AsObject
    Returns an object rather than string based represantation for name servers (for easier display purposes)

    .EXAMPLE
    # Standard way
    Find-DMARCRecord -DomainName 'evotec.pl', 'evotec.xyz' | Format-Table *

    .EXAMPLE
    # Https way via Cloudflare
    Find-DMARCRecord -DomainName 'evotec.pl', 'evotec.xyz' -DNSProvider Cloudflare | Format-Table *

    .EXAMPLE
    # Https way via Google
    Find-DMARCRecord -DomainName 'evotec.pl', 'evotec.xyz' -DNSProvider Google | Format-Table *

    .NOTES
    General notes
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ValueFromPipeline, Position = 0)][Array] $DomainName,
        [string] $DnsServer,
        [ValidateSet('Cloudflare', 'Google')][string] $DNSProvider,
        [switch] $AsHashTable,
        [switch] $AsObject
    )
    process {
        foreach ($Domain in $DomainName) {
            if ($Domain -is [string]) {
                $D = $Domain
            } elseif ($Domain -is [System.Collections.IDictionary]) {
                $D = $Domain.DomainName
                if (-not $D) {
                    Write-Warning 'Find-DMARCRecord - property DomainName is required when passing Array of Hashtables'
                }
            }
            $Splat = @{
                Name        = "_dmarc.$D"
                Type        = 'TXT'
                ErrorAction = 'Stop'
            }
            try {
                if ($DNSProvider) {
                    $DNSRecord = Resolve-DnsQueryRest @Splat -All -DNSProvider $DnsProvider
                } else {
                    if ($DnsServer) {
                        $Splat['Server'] = $DnsServer
                    }
                    $DNSRecord = Resolve-DnsQuery @Splat -All
                }
                $DNSRecordAnswers = $DNSRecord.Answers | Where-Object Text -Match 'DMARC1'
                if (-not $AsObject) {
                    $MailRecord = [ordered] @{
                        Name        = $D
                        Count       = $DNSRecordAnswers.Count
                        TimeToLive  = $DNSRecordAnswers.TimeToLive -join '; '
                        DMARC       = $DNSRecordAnswers.Text -join '; '
                        QueryServer = $DNSRecord.NameServer -join '; '
                    }
                } else {
                    $MailRecord = [ordered] @{
                        Name        = $D
                        Count       = $DNSRecordAnswers.Count
                        TimeToLive  = $DNSRecordAnswers.TimeToLive
                        DMARC       = $DNSRecordAnswers.Text
                        QueryServer = $DNSRecord.NameServer
                    }
                }
            } catch {
                $MailRecord = [ordered] @{
                    Name        = $D
                    Count       = 0
                    TimeToLive  = ''
                    DMARC       = ''
                    QueryServer = ''
                }
                Write-Warning "Find-DMARCRecord - $_"
            }
            if ($AsHashTable) {
                $MailRecord
            } else {
                [PSCustomObject] $MailRecord
            }
        }
    }
}
function Find-DNSBL {
    <#
    .SYNOPSIS
    Searches DNSBL if particular IP is blocked on DNSBL.

    .DESCRIPTION
    Searches DNSBL if particular IP is blocked on DNSBL.

    .PARAMETER IP
    IP to check if it exists on DNSBL

    .PARAMETER BlockListServers
    Provide your own blocklist of servers

    .PARAMETER All
    Return All entries. By default it returns only those on DNSBL.

    .PARAMETER DNSServer
    Allows to choose DNS IP address to ask for DNS query. By default uses system ones.

    .PARAMETER DNSProvider
    Allows to choose DNS Provider that will be used for HTTPS based DNS query (Cloudlare or Google)

    .EXAMPLE
    Find-DNSBL -IP '89.74.48.96' | Format-Table

    .EXAMPLE
    Find-DNSBL -IP '89.74.48.96', '89.74.48.97', '89.74.48.98' | Format-Table

    .EXAMPLE
    Find-DNSBL -IP '89.74.48.96' -DNSServer 1.1.1.1 | Format-Table

    .EXAMPLE
    Find-DNSBL -IP '89.74.48.96' -DNSProvider Cloudflare | Format-Table

    .NOTES
    General notes
    #>
    [alias('Find-BlackList', 'Find-BlockList')]
    [cmdletBinding(DefaultParameterSetName = 'Default')]
    param(
        [Parameter(Mandatory)][string[]] $IP,
        [string[]] $BlockListServers = $Script:BlockList,
        [switch] $All,
        [Parameter(ParameterSetName = 'DNSServer')][string] $DNSServer,
        [Parameter(ParameterSetName = 'DNSProvider')][ValidateSet('Cloudflare', 'Google')][string] $DNSProvider
    )
    foreach ($I in $IP) {
        foreach ($Server in $BlockListServers) {
            [string] $FQDN = $I -replace '^(\d+)\.(\d+)\.(\d+)\.(\d+)$', "`$4.`$3.`$2.`$1.$Server"
            if (-not $DNSProvider) {
                $DnsQuery = Resolve-DnsQuery -Name $FQDN -Type A -Server $DNSServer -All
                $Answer = $DnsQuery.Answers[0].Address.IPAddressToString
                $IsListed = $null -ne $Answer
            } else {
                $DnsQuery = Resolve-DnsQueryRest -Name $FQDN -Type A -DNSProvider $DNSProvider -All
                $Answer = $DnsQuery.Answers.Address
                $IsListed = $null -ne $DnsQuery.Answers
            }
            $Result = [PSCustomObject] @{
                IP         = $I
                FQDN       = $FQDN
                BlackList  = $Server
                IsListed   = $IsListed
                Answer     = $Answer
                TTL        = $DnsQuery.Answers.TimeToLive
                NameServer = $DnsQuery.NameServer
            }
            if (-not $All -and $Result.IsListed -eq $false) {
                continue
            }
            $Result
        }
    }
}

function Find-MxRecord {
    <#
    .SYNOPSIS
    Queries DNS to provide MX information

    .DESCRIPTION
    Queries DNS to provide MX information

    .PARAMETER DomainName
    Name/DomainName to query for MX record

    .PARAMETER ResolvePTR
    Parameter description

    .PARAMETER DnsServer
    Allows to choose DNS IP address to ask for DNS query. By default uses system ones.

    .PARAMETER DNSProvider
    Allows to choose DNS Provider that will be used for HTTPS based DNS query (Cloudlare or Google)

    .PARAMETER AsHashTable
    Returns Hashtable instead of PSCustomObject

    .PARAMETER AsObject
    Returns an object rather than string based represantation for name servers (for easier display purposes)

    .PARAMETER Separate
    Returns each MX record separatly

    .EXAMPLE
    # Standard way
    Find-MxRecord -DomainName 'evotec.pl', 'evotec.xyz' | Format-Table *

    .EXAMPLE
    # Https way via Cloudflare
    Find-MxRecord -DomainName 'evotec.pl', 'evotec.xyz' -DNSProvider Cloudflare | Format-Table *

    .EXAMPLE
    # Https way via Google
    Find-MxRecord -DomainName 'evotec.pl', 'evotec.xyz' -DNSProvider Google | Format-Table *

    .EXAMPLE
    # Standard way with ResolvePTR
    Find-MxRecord -DomainName 'evotec.pl', 'evotec.xyz' -ResolvePTR | Format-Table *

    .EXAMPLE
    # Https way via Cloudflare with ResolvePTR
    Find-MxRecord -DomainName 'evotec.pl', 'evotec.xyz' -DNSProvider Cloudflare -ResolvePTR | Format-Table *

    .EXAMPLE
    # Https way via Google with ResolvePTR
    Find-MxRecord -DomainName 'evotec.pl', 'evotec.xyz' -DNSProvider Google -ResolvePTR | Format-Table *

    .NOTES
    General notes
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ValueFromPipeline, Position = 0)][Array]$DomainName,
        [string] $DnsServer,
        [ValidateSet('Cloudflare', 'Google')][string] $DNSProvider,
        [switch] $ResolvePTR,
        [switch] $AsHashTable,
        [switch] $Separate,
        [switch] $AsObject
    )
    process {
        foreach ($Domain in $DomainName) {
            if ($Domain -is [string]) {
                $D = $Domain
            } elseif ($Domain -is [System.Collections.IDictionary]) {
                $D = $Domain.DomainName
                if (-not $D) {
                    Write-Warning 'Find-MxRecord - property DomainName is required when passing Array of Hashtables'
                }
            }
            $Splat = @{
                Name        = $D
                Type        = 'MX'
                ErrorAction = 'SilentlyContinue'
            }
            if ($DNSProvider) {
                $MX = Resolve-DnsQueryRest @Splat -All -DNSProvider $DnsProvider
            } else {
                if ($DnsServer) {
                    $Splat['Server'] = $DnsServer
                }
                $MX = Resolve-DnsQuery @Splat -All
            }
            [Array] $MXRecords = foreach ($MXRecord in $MX.Answers) {
                $MailRecord = [ordered] @{
                    Name        = $D
                    Preference  = $MXRecord.Preference
                    TimeToLive  = $MXRecord.TimeToLive
                    MX          = ($MXRecord.Exchange) -replace '.$'
                    QueryServer = $MX.NameServer
                }
                [Array] $IPAddresses = foreach ($Record in $MX.Answers.Exchange) {
                    $Splat = @{
                        Name        = $Record
                        Type        = 'A'
                        ErrorAction = 'SilentlyContinue'
                    }
                    if ($DNSProvider) {
                        (Resolve-DnsQueryRest @Splat -DNSProvider $DnsProvider) | ForEach-Object { $_.Address }
                    } else {
                        if ($DnsServer) {
                            $Splat['Server'] = $DnsServer
                        }
                        (Resolve-DnsQuery @Splat) | ForEach-Object { $_.Address.IPAddressToString }
                    }
                }
                $MailRecord['IPAddress'] = $IPAddresses
                if ($ResolvePTR) {
                    $MailRecord['PTR'] = foreach ($IP in $IPAddresses) {
                        $Splat = @{
                            Name        = $IP
                            Type        = 'PTR'
                            ErrorAction = 'SilentlyContinue'
                        }
                        if ($DNSProvider) {
                            (Resolve-DnsQueryRest @Splat -DNSProvider $DnsProvider) | ForEach-Object { $_.Text -replace '.$' }
                        } else {
                            if ($DnsServer) {
                                $Splat['Server'] = $DnsServer
                            }
                            (Resolve-DnsQuery @Splat) | ForEach-Object { $_.PtrDomainName -replace '.$' }
                        }
                    }
                }
                $MailRecord
            }
            if ($Separate) {
                foreach ($MXRecord in $MXRecords) {
                    if ($AsHashTable) {
                        $MXRecord
                    } else {
                        [PSCustomObject] $MXRecord
                    }
                }
            } else {
                if (-not $AsObject) {
                    $MXRecord = [ordered] @{
                        Name        = $D
                        Count       = $MXRecords.Count
                        Preference  = $MXRecords.Preference -join '; '
                        TimeToLive  = $MXRecords.TimeToLive -join '; '
                        MX          = $MXRecords.MX -join '; '
                        IPAddress   = ($MXRecords.IPAddress | Sort-Object -Unique) -join '; '
                        QueryServer = $MXRecords.QueryServer -join '; '
                    }
                    if ($ResolvePTR) {
                        $MXRecord['PTR'] = ($MXRecords.PTR | Sort-Object -Unique) -join '; '
                    }
                } else {
                    $MXRecord = [ordered] @{
                        Name        = $D
                        Count       = $MXRecords.Count
                        Preference  = $MXRecords.Preference
                        TimeToLive  = $MXRecords.TimeToLive
                        MX          = $MXRecords.MX
                        IPAddress   = ($MXRecords.IPAddress | Sort-Object -Unique)
                        QueryServer = $MXRecords.QueryServer
                    }
                    if ($ResolvePTR) {
                        $MXRecord['PTR'] = ($MXRecords.PTR | Sort-Object -Unique)
                    }
                }
                if ($AsHashTable) {
                    $MXRecord
                } else {
                    [PSCustomObject] $MXRecord
                }
            }
        }
    }
}
function Find-SPFRecord {
    <#
    .SYNOPSIS
    Queries DNS to provide SPF information

    .DESCRIPTION
    Queries DNS to provide SPF information

    .PARAMETER DomainName
    Name/DomainName to query for SPF record

    .PARAMETER DnsServer
    Allows to choose DNS IP address to ask for DNS query. By default uses system ones.

    .PARAMETER DNSProvider
    Allows to choose DNS Provider that will be used for HTTPS based DNS query (Cloudlare or Google)

    .PARAMETER AsHashTable
    Returns Hashtable instead of PSCustomObject

    .PARAMETER AsObject
    Returns an object rather than string based represantation for name servers (for easier display purposes)

    .EXAMPLE
    # Standard way
    Find-SPFRecord -DomainName 'evotec.pl', 'evotec.xyz' | Format-Table *

    .EXAMPLE
    # Https way via Cloudflare
    Find-SPFRecord -DomainName 'evotec.pl', 'evotec.xyz' -DNSProvider Cloudflare | Format-Table *

    .EXAMPLE
    # Https way via Google
    Find-SPFRecord -DomainName 'evotec.pl', 'evotec.xyz' -DNSProvider Google | Format-Table *

    .NOTES
    General notes
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ValueFromPipeline, Position = 0)][Array]$DomainName,
        [string] $DnsServer,
        [ValidateSet('Cloudflare', 'Google')][string] $DNSProvider,
        [switch] $AsHashTable,
        [switch] $AsObject
    )
    process {
        foreach ($Domain in $DomainName) {
            if ($Domain -is [string]) {
                $D = $Domain
            } elseif ($Domain -is [System.Collections.IDictionary]) {
                $D = $Domain.DomainName
                if (-not $D) {
                    Write-Warning 'Find-MxRecord - property DomainName is required when passing Array of Hashtables'
                }
            }
            $Splat = @{
                Name        = $D
                Type        = 'txt'
                ErrorAction = 'Stop'
            }
            try {
                if ($DNSProvider) {
                    $DNSRecord = Resolve-DnsQueryRest @Splat -All -DNSProvider $DnsProvider
                } else {
                    if ($DnsServer) {
                        $Splat['Server'] = $DnsServer
                    }
                    $DNSRecord = Resolve-DnsQuery @Splat -All
                }
                $DNSRecordAnswers = $DNSRecord.Answers | Where-Object Text -Match 'spf1'
                if (-not $AsObject) {
                    $MailRecord = [ordered] @{
                        Name        = $D
                        Count       = $DNSRecordAnswers.Count
                        TimeToLive  = $DNSRecordAnswers.TimeToLive -join '; '
                        SPF         = $DNSRecordAnswers.Text -join '; '
                        QueryServer = $DNSRecord.NameServer
                    }
                } else {
                    $MailRecord = [ordered] @{
                        Name        = $D
                        Count       = $DNSRecordAnswers.Count
                        TimeToLive  = $DNSRecordAnswers.TimeToLive
                        SPF         = $DNSRecordAnswers.Text
                        QueryServer = $DNSRecord.NameServer
                    }
                }
            } catch {
                $MailRecord = [ordered] @{
                    Name        = $D
                    Count       = 0
                    TimeToLive  = ''
                    SPF         = ''
                    QueryServer = ''
                }
                Write-Warning "Find-SPFRecord - $_"
            }
            if ($AsHashTable) {
                $MailRecord
            } else {
                [PSCustomObject] $MailRecord
            }
        }
    }
}
function Get-IMAPFolder {
    [cmdletBinding()]
    param(
        [System.Collections.IDictionary] $Client,
        [MailKit.FolderAccess] $FolderAccess = [MailKit.FolderAccess]::ReadOnly
    )
    if ($Client) {
        $Folder = $Client.Data.Inbox
        $null = $Folder.Open($FolderAccess)

        Write-Verbose "Get-IMAPMessage - Total messages $($Folder.Count), Recent messages $($Folder.Recent)"
        $Client.Messages = $Folder
        $Client.Count = $Folder.Count
        $Client.Recent = $Folder.Recent
        $Client
    } else {
        Write-Verbose 'Get-IMAPMessage - Client not connected?'
    }
}
function Get-IMAPMessage {
    [cmdletBinding()]
    param(
        [Parameter()][System.Collections.IDictionary] $Client,
        [MailKit.FolderAccess] $FolderAccess = [MailKit.FolderAccess]::ReadOnly
    )
    if ($Client) {
        $Folder = $Client.Data.Inbox
        $null = $Folder.Open($FolderAccess)

        Write-Verbose "Get-IMAPMessage - Total messages $($Folder.Count), Recent messages $($Folder.Recent)"
        $Client.Folder = $Folder
    } else {
        Write-Verbose 'Get-IMAPMessage - Client not connected?'
    }
}
function Get-MailFolder {
    [cmdletBinding()]
    param(
        [string] $UserPrincipalName,
        [PSCredential] $Credential
    )
    if ($Credential) {
        $AuthorizationData = ConvertFrom-GraphCredential -Credential $Credential
    } else {
        return
    }
    if ($AuthorizationData.ClientID -eq 'MSAL') {
        $Authorization = Connect-O365GraphMSAL -ApplicationKey $AuthorizationData.ClientSecret
    } else {
        $Authorization = Connect-O365Graph -ApplicationID $AuthorizationData.ClientID -ApplicationKey $AuthorizationData.ClientSecret -TenantDomain $AuthorizationData.DirectoryID -Resource https://graph.microsoft.com
    }
    Invoke-O365Graph -Headers $Authorization -Uri "/users/$UserPrincipalName/mailFolders" -Method GET
}
function Get-MailMessage {
    [cmdletBinding()]
    param(
        [string] $UserPrincipalName,
        [PSCredential] $Credential,
        [switch] $All,
        [int] $Limit = 10,
        [ValidateSet(
            'createdDateTime', 'lastModifiedDateTime', 'changeKey', 'categories', 'receivedDateTime', 'sentDateTime', 'hasAttachments', 'internetMessageId', 'subject', 'bodyPreview', 'importance', 'parentFolderId', 'conversationId', 'conversationIndex', 'isDeliveryReceiptRequested', 'isReadReceiptRequested', 'isRead', 'isDraft', 'webLink', 'inferenceClassification', 'body', 'sender', 'from', 'toRecipients', 'ccRecipients', 'bccRecipients', 'replyTo', 'flag')
        ][string[]] $Property,
        [string] $Filter
    )
    if ($Credential) {
        $AuthorizationData = ConvertFrom-GraphCredential -Credential $Credential
    } else {
        return
    }
    if ($AuthorizationData.ClientID -eq 'MSAL') {
        $Authorization = Connect-O365GraphMSAL -ApplicationKey $AuthorizationData.ClientSecret
    } else {
        $Authorization = Connect-O365Graph -ApplicationID $AuthorizationData.ClientID -ApplicationKey $AuthorizationData.ClientSecret -TenantDomain $AuthorizationData.DirectoryID -Resource https://graph.microsoft.com
    }
    $Uri = "/users/$UserPrincipalName/messages"
    $Addon = '?'
    if ($Property) {
        $Poperties = $Property -join ','
        $Addon = -join ($Addon, "`$Select=$Poperties")
    }
    if ($Filter) {
        $Addon = -join ($Addon, "&`$filter=$Filter")
    }
    #Write-Verbose $Addon
    #$Addon = [System.Web.HttpUtility]::UrlEncode($Addon)
    if ($Addon.Length -gt 1) {
        $Uri = -join ($Uri, $Addon)
    }

    Write-Verbose "Get-MailMessage - Executing $Uri"
    $Uri = [uri]::EscapeUriString($Uri)
    Write-Verbose "Get-MailMessage - Executing $Uri"
    if ($All) {
        Invoke-O365Graph -Headers $Authorization -Uri $Uri -Method GET
    } else {
        Invoke-O365Graph -Headers $Authorization -Uri $Uri -Method GET | Select-Object -First $Limit
    }
}


function Get-POPMessage {
    [alias('Get-POP3Message')]
    [cmdletBinding()]
    param(
        [Parameter()][System.Collections.IDictionary] $Client,
        [int] $Index,
        [int] $Count = 1,
        [switch] $All
    )
    if ($Client -and $Client.Data) {
        if ($All) {
            $Client.Data.GetMessages($Index, $Count)
        } else {
            if ($Index -lt $Client.Data.Count) {
                $Client.Data.GetMessages($Index, $Count)
            } else {
                Write-Warning "Get-POP3Message - Index is out of range. Use index less than $($Client.Data.Count)."
            }
        }
    } else {
        Write-Warning 'Get-POP3Message - Is POP3 connected?'
    }
    <#
    $Client.Data.GetMessage
    MimeKit.MimeMessage GetMessage(int index, System.Threading.CancellationToken cancellationToken, MailKit.ITransferProgress progress)
    MimeKit.MimeMessage IMailSpool.GetMessage(int index, System.Threading.CancellationToken cancellationToken, MailKit.ITransferProgress progress)
    #>
    <#
    $Client.Data.GetMessages
    System.Collections.Generic.IList[MimeKit.MimeMessage] GetMessages(System.Collections.Generic.IList[int] indexes, System.Threading.CancellationToken cancellationToken, MailKit.ITransferProgress progress)
    System.Collections.Generic.IList[MimeKit.MimeMessage] GetMessages(int startIndex, int count, System.Threading.CancellationToken cancellationToken, MailKit.ITransferProgress progress)
    System.Collections.Generic.IList[MimeKit.MimeMessage] IMailSpool.GetMessages(System.Collections.Generic.IList[int] indexes, System.Threading.CancellationTokencancellationToken, MailKit.ITransferProgress progress)
    System.Collections.Generic.IList[MimeKit.MimeMessage] IMailSpool.GetMessages(int startIndex, int count, System.Threading.CancellationToken cancellationToken, MailKit.ITransferProgress progress)
    #>
}
function Resolve-DnsQuery {
    [cmdletBinding()]
    param(
        [alias('Query')][Parameter(Mandatory)][string] $Name,
        [Parameter(Mandatory)][DnsClient.QueryType] $Type,
        [string] $Server,
        [switch] $All
    )
    if ($Server) {
        if ($Server -like '*:*') {
            $SplittedServer = $Server.Split(':')
            [System.Net.IPAddress] $IpAddress = $SplittedServer[0]
            $EndPoint = [System.Net.IPEndPoint]::new($IpAddress, $SplittedServer[1]) ##(IPAddress.Parse("127.0.0.1"), 8600);
        } else {
            [System.Net.IPAddress] $IpAddress = $Server
            $EndPoint = [System.Net.IPEndPoint]::new($IpAddress, 53) ##(IPAddress.Parse("127.0.0.1"), 8600);
        }
        $Lookup = [DnsClient.LookupClient]::new($EndPoint)
    } else {
        $Lookup = [DnsClient.LookupClient]::new()
    }
    if ($Type -eq [DnsClient.QueryType]::PTR) {
        #$Lookup = [DnsClient.LookupClient]::new()
        $Results = $Lookup.QueryReverseAsync($Name) | Wait-Task
        $Name = $Results.Answers.DomainName.Original
    }
    $Results = $Lookup.Query($Name, $Type)
    if ($All) {
        $Results
    } else {
        $Results.Answers
    }
}
function Resolve-DnsQueryRest {
    <#
    .SYNOPSIS
    Provides basic DNS Query via HTTPS

    .DESCRIPTION
    Provides basic DNS Query via HTTPS - tested only for use cases within Mailozaurr

    .PARAMETER DNSProvider
    Allows to choose DNS Provider that will be used for HTTPS based DNS query (Cloudlare or Google). Default is Cloudflare

    .PARAMETER Name
    Name/DomainName to query DNS

    .PARAMETER Type
    Type of a query A, PTR, MX and so on

    .PARAMETER All
    Returns full output rather than just custom, translated data

    .EXAMPLE
    Resolve-DnsQueryRest -Name 'evotec.pl' -Type TXT -DNSProvider Cloudflare

    .NOTES
    General notes
    #>
    [cmdletBinding()]
    param(
        [alias('Query')][Parameter(Mandatory, Position = 0)][string] $Name,
        [Parameter(Mandatory, Position = 1)][string] $Type,
        [ValidateSet('Cloudflare', 'Google')][string] $DNSProvider = 'Cloudflare',
        [switch] $All
    )
    if ($Type -eq 'PTR') {
        $Name = $Name -replace '^(\d+)\.(\d+)\.(\d+)\.(\d+)$', '$4.$3.$2.$1.in-addr.arpa'
    }
    if ($DNSProvider -eq 'Cloudflare') {
        $Q = Invoke-RestMethod -Uri "https://cloudflare-dns.com/dns-query?ct=application/dns-json&name=$Name&type=$Type"
    } else {
        $Q = Invoke-RestMethod -Uri "https://dns.google.com/resolve?name=$Name&type=$Type"
    }
    $Answers = foreach ($Answer in $Q.Answer) {
        if ($Type -eq 'MX') {
            $Data = $Answer.data -split ' '
            [PSCustomObject] @{
                Name       = $Answer.Name
                Count      = $Answer.Type
                TimeToLive = $Answer.TTL
                Exchange   = $Data[1]
                Preference = $Data[0]
            }
        } elseif ($Type -eq 'A') {
            [PSCustomObject] @{
                Name       = $Answer.Name
                Count      = $Answer.Type
                TimeToLive = $Answer.TTL
                Address    = $Answer.data #.TrimStart('"').TrimEnd('"')
            }
        } else {
            [PSCustomObject] @{
                Name       = $Answer.Name
                Count      = $Answer.Type
                TimeToLive = $Answer.TTL
                Text       = $Answer.data.TrimStart('"').TrimEnd('"')
            }
        }
    }
    if ($All) {
        [PSCustomObject] @{
            NameServer = if ($DNSProvider -eq 'Cloudflare') { 'cloudflare-dns.com' } else { 'dns.google.com' }
            Answers    = $Answers
        }
    } else {
        $Answers
    }
}

Register-ArgumentCompleter -CommandName Resolve-DnsQueryRest -ParameterName Type -ScriptBlock $Script:DNSQueryTypes
function Save-MailMessage {
    [cmdletBinding()]
    param(
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName, Position = 0)][PSCustomObject[]] $Message,
        [string] $Path
    )
    Begin {
        $ResolvedPath = Convert-Path -LiteralPath $Path
    }
    Process {
        if (-not $ResolvedPath) {
            return
        }
        foreach ($M in $Message) {
            if ($M) {
                if ($M.Body -and $M.Content) {
                    Write-Verbose "Processing $($M.changekey)"
                    $RandomFileName = [io.path]::GetRandomFileName()
                    $RandomFileName = [io.path]::ChangeExtension($RandomFileName, 'html')
                    $FilePath = [io.path]::Combine($ResolvedPath, $RandomFileName)
                    try {
                        $M.Body.Content | Out-File -FilePath $FilePath -ErrorAction Stop
                    } catch {
                        Write-Warning "Save-MailMessage - Coultn't save file to $FilePath. Error: $($_.Exception.Message)"
                    }
                } else {
                    Write-Warning "Save-MailMessage - Message doesn't contain Body property. Did you request it? (eTag: $($M.'@odata.etag')"
                }
            }
        }
    }
    End {}
}
function Save-POPMessage {
    [alias('Save-POP3Message')]
    [cmdletBinding()]
    param(
        [Parameter()][System.Collections.IDictionary] $Client,
        [Parameter(Mandatory)][int] $Index,
        [Parameter(Mandatory)][string] $Path #,
        # [int] $Count = 1,
        #[switch] $All
    )
    if ($Client -and $Client.Data) {
        if ($All) {
            # $Client.Data.GetMessages($Index, $Count)
        } else {
            if ($Index -lt $Client.Data.Count) {
                $Client.Data.GetMessage($Index).WriteTo($Path)
            } else {
                Write-Warning "Save-POP3Message - Index is out of range. Use index less than $($Client.Data.Count)."
            }
        }
    } else {
        Write-Warning 'Save-POP3Message - Is POP3 connected?'
    }
}
function Send-EmailMessage {
    <#
    .SYNOPSIS
    The Send-EmailMessage cmdlet sends an email message from within PowerShell.

    .DESCRIPTION
    The Send-EmailMessage cmdlet sends an email message from within PowerShell. It replaces Send-MailMessage by Microsoft which is deprecated.

    .PARAMETER Server
    Specifies the name of the SMTP server that sends the email message.

    .PARAMETER Port
    Specifies an alternate port on the SMTP server. The default value is 587.

    .PARAMETER From
    This parameter specifies the sender's email address.

    .PARAMETER ReplyTo
    This property indicates the reply address. If you don't set this property, the Reply address is same as From address.

    .PARAMETER Cc
    Specifies the email addresses to which a carbon copy (CC) of the email message is sent.

    .PARAMETER Bcc
    Specifies the email addresses that receive a copy of the mail but are not listed as recipients of the message.

    .PARAMETER To
    Specifies the recipient's email address. If there are multiple recipients, separate their addresses with a comma (,)

    .PARAMETER Subject
    The Subject parameter isn't required. This parameter specifies the subject of the email message.

    .PARAMETER Priority
    Specifies the priority of the email message. Normal is the default. The acceptable values for this parameter are Normal, High, and Low.

    .PARAMETER Encoding
    Specifies the type of encoding for the target file. It's recommended to not change it.

    The acceptable values for this parameter are as follows:

    default:
    ascii: Uses the encoding for the ASCII (7-bit) character set.
    bigendianunicode: Encodes in UTF-16 format using the big-endian byte order.
    oem: Uses the default encoding for MS-DOS and console programs.
    unicode: Encodes in UTF-16 format using the little-endian byte order.
    utf7: Encodes in UTF-7 format.
    utf8: Encodes in UTF-8 format.
    utf32: Encodes in UTF-32 format.

    .PARAMETER DeliveryNotificationOption
    Specifies the delivery notification options for the email message. You can specify multiple values. None is the default value. The alias for this parameter is DNO. The delivery notifications are sent to the address in the From parameter. Multiple options can be chosen.

    .PARAMETER DeliveryStatusNotificationType
    Specifies delivery status notification type. Options are Full, HeadersOnly, Unspecified

    .PARAMETER Credential
    Specifies a user account that has permission to perform this action. The default is the current user.
    Type a user name, such as User01 or Domain01\User01. Or, enter a PSCredential object, such as one from the Get-Credential cmdlet.
    Credentials are stored in a PSCredential object and the password is stored as a SecureString.

    Credential parameter is also use to securely pass tokens/api keys for Graph API/oAuth2/SendGrid

    .PARAMETER Username
    Specifies UserName to use to login to server

    .PARAMETER Password
    Specifies Password to use to login to server. This is ClearText option and should not be used, unless used with SecureString

    .PARAMETER SecureSocketOptions
    Specifies secure socket option: None, Auto, StartTls, StartTlsWhenAvailable, SslOnConnect. Default is Auto.

    .PARAMETER UseSsl
    Specifies using StartTLS option. It's recommended to leave it disabled and use SecureSocketOptions which should take care of all security needs

    .PARAMETER SkipCertificateRevocation
    Specifies to skip certificate revocation check

    .PARAMETER SkipCertificateValidatation
    Specifies to skip certficate validation. Useful when using IP Address or self-generated certificates.

    .PARAMETER HTML
    HTML content to send email

    .PARAMETER Text
    Text content to send email. With SMTP one can define both HTML and Text. For SendGrid and Office 365 Graph API only HTML or Text will be used with HTML having priority

    .PARAMETER Attachment
    Specifies the path and file names of files to be attached to the email message.

    .PARAMETER Timeout
    Maximum time to wait to send an email via SMTP

    .PARAMETER oAuth2
    Send email via oAuth2

    .PARAMETER Graph
    Send email via Office 365 Graph API

    .PARAMETER SendGrid
    Send email via SendGrid API

    .PARAMETER SeparateTo
    Option separates each To field into separate emails (sent as one query). Supported by SendGrid only! BCC/CC are skipped when this mode is used.

    .PARAMETER DoNotSaveToSentItems
    Do not save email to SentItems when sending with Office 365 Graph API

    .PARAMETER Email
    Compatibility parameter for Send-Email cmdlet from PSSharedGoods

    .PARAMETER Suppress
    Do not display summary in [PSCustomObject]

    .PARAMETER AsSecureString
    Informs command that password provided is secure string, rather than clear text

    .EXAMPLE
    if (-not $MailCredentials) {
        $MailCredentials = Get-Credential
    }

    Send-EmailMessage -From @{ Name = 'Przemysław Kłys'; Email = 'przemyslaw.klys@test.pl' } -To 'przemyslaw.klys@test.pl' `
        -Server 'smtp.office365.com' -SecureSocketOptions Auto -Credential $MailCredentials -HTML $Body -DeliveryNotificationOption OnSuccess -Priority High `
        -Subject 'This is another test email'

    .EXAMPLE
    if (-not $MailCredentials) {
        $MailCredentials = Get-Credential
    }
    # this is simple replacement (drag & drop to Send-MailMessage)
    Send-EmailMessage -To 'przemyslaw.klys@test.pl' -Subject 'Test' -Body 'test me' -SmtpServer 'smtp.office365.com' -From 'przemyslaw.klys@test.pl' `
        -Attachments "$PSScriptRoot\README.MD" -Cc 'przemyslaw.klys@test.pl' -Priority High -Credential $MailCredentials `
        -UseSsl -Port 587 -Verbose

    .EXAMPLE
    # Use SendGrid Api
    $Credential = ConvertTo-SendGridCredential -ApiKey 'YourKey'

    Send-EmailMessage -From 'przemyslaw.klys@evo.cool' `
        -To 'przemyslaw.klys@evotec.pl', 'evotectest@gmail.com' `
        -Body 'test me Przemysław Kłys' `
        -Priority High `
        -Subject 'This is another test email' `
        -SendGrid `
        -Credential $Credential `
        -Verbose

    .EXAMPLE
    # It seems larger HTML is not supported. Online makes sure it uses less libraries inline
    # it may be related to not escaping chars properly for JSON, may require investigation
    $Body = EmailBody {
        EmailText -Text 'This is my text'
        EmailTable -DataTable (Get-Process | Select-Object -First 5 -Property Name, Id, PriorityClass, CPU, Product)
    } -Online

    # Credentials for Graph
    $ClientID = '0fb383f1'
    $DirectoryID = 'ceb371f6'
    $ClientSecret = 'VKDM_'

    $Credential = ConvertTo-GraphCredential -ClientID $ClientID -ClientSecret $ClientSecret -DirectoryID $DirectoryID

    # Sending email
    Send-EmailMessage -From @{ Name = 'Przemysław Kłys'; Email = 'przemyslaw.klys@test1.pl' } -To 'przemyslaw.klys@test.pl' `
        -Credential $Credential -HTML $Body -Subject 'This is another test email 1' -Graph -Verbose -Priority High

    .EXAMPLE
    # Using OAuth2 for Office 365
    $ClientID = '4c1197dd-53'
    $TenantID = 'ceb371f6-87'

    $CredentialOAuth2 = Connect-oAuthO365 -ClientID $ClientID -TenantID $TenantID

    Send-EmailMessage -From @{ Name = 'Przemysław Kłys'; Email = 'test@evotec.pl' } -To 'test@evotec.pl' `
        -Server 'smtp.office365.com' -HTML $Body -Text $Text -DeliveryNotificationOption OnSuccess -Priority High `
        -Subject 'This is another test email' -SecureSocketOptions Auto -Credential $CredentialOAuth2 -oAuth2

    .NOTES
    General notes
    #>
    [cmdletBinding(DefaultParameterSetName = 'Compatibility', SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName = 'SecureString')]

        [Parameter(ParameterSetName = 'oAuth')]
        [Parameter(ParameterSetName = 'Compatibility')]
        [alias('SmtpServer')][string] $Server,

        [Parameter(ParameterSetName = 'SecureString')]

        [Parameter(ParameterSetName = 'oAuth')]
        [Parameter(ParameterSetName = 'Compatibility')]
        [int] $Port = 587,

        [Parameter(ParameterSetName = 'SecureString')]

        [Parameter(ParameterSetName = 'oAuth')]
        [Parameter(ParameterSetName = 'Graph')]
        [Parameter(ParameterSetName = 'Compatibility')]
        [Parameter(ParameterSetName = 'SendGrid')]
        [object] $From,

        [Parameter(ParameterSetName = 'SecureString')]

        [Parameter(ParameterSetName = 'oAuth')]
        [Parameter(ParameterSetName = 'Graph')]
        [Parameter(ParameterSetName = 'Compatibility')]
        [Parameter(ParameterSetName = 'SendGrid')]
        [string] $ReplyTo,

        [Parameter(ParameterSetName = 'SecureString')]

        [Parameter(ParameterSetName = 'oAuth')]
        [Parameter(ParameterSetName = 'Graph')]
        [Parameter(ParameterSetName = 'Compatibility')]
        [Parameter(ParameterSetName = 'SendGrid')]
        [string[]] $Cc,

        [Parameter(ParameterSetName = 'SecureString')]

        [Parameter(ParameterSetName = 'oAuth')]
        [Parameter(ParameterSetName = 'Graph')]
        [Parameter(ParameterSetName = 'Compatibility')]
        [Parameter(ParameterSetName = 'SendGrid')]
        [string[]] $Bcc,

        [Parameter(ParameterSetName = 'SecureString')]
        [Parameter(ParameterSetName = 'oAuth')]
        [Parameter(ParameterSetName = 'Graph')]
        [Parameter(ParameterSetName = 'Compatibility')]
        [Parameter(ParameterSetName = 'SendGrid')]
        [string[]] $To,

        [Parameter(ParameterSetName = 'SecureString')]
        [Parameter(ParameterSetName = 'oAuth')]
        [Parameter(ParameterSetName = 'Graph')]
        [Parameter(ParameterSetName = 'Compatibility')]
        [Parameter(ParameterSetName = 'SendGrid')]
        [string] $Subject,

        [Parameter(ParameterSetName = 'SecureString')]

        [Parameter(ParameterSetName = 'oAuth')]
        [Parameter(ParameterSetName = 'Graph')]
        [Parameter(ParameterSetName = 'Compatibility')]
        [Parameter(ParameterSetName = 'SendGrid')]
        [alias('Importance')][ValidateSet('Low', 'Normal', 'High')][string] $Priority,

        [Parameter(ParameterSetName = 'SecureString')]

        [Parameter(ParameterSetName = 'oAuth')]
        [Parameter(ParameterSetName = 'Compatibility')]
        [ValidateSet('ASCII', 'BigEndianUnicode', 'Default', 'Unicode', 'UTF32', 'UTF7', 'UTF8')][string] $Encoding = 'Default',

        [Parameter(ParameterSetName = 'SecureString')]
        [Parameter(ParameterSetName = 'oAuth')]
        [Parameter(ParameterSetName = 'Compatibility')]
        [ValidateSet('None', 'OnSuccess', 'OnFailure', 'Delay', 'Never')][string[]] $DeliveryNotificationOption,

        [Parameter(ParameterSetName = 'SecureString')]
        [Parameter(ParameterSetName = 'oAuth')]
        [Parameter(ParameterSetName = 'Compatibility')]
        [MailKit.Net.Smtp.DeliveryStatusNotificationType] $DeliveryStatusNotificationType,

        [Parameter(ParameterSetName = 'oAuth')]
        [Parameter(ParameterSetName = 'Graph', Mandatory)]
        [Parameter(ParameterSetName = 'Compatibility')]
        [Parameter(ParameterSetName = 'SendGrid', Mandatory)]
        [pscredential] $Credential,

        [Parameter(ParameterSetName = 'SecureString')]
        [string] $Username,

        [Parameter(ParameterSetName = 'SecureString')]

        [string] $Password,

        [Parameter(ParameterSetName = 'SecureString')]

        [Parameter(ParameterSetName = 'oAuth')]
        [Parameter(ParameterSetName = 'Compatibility')]
        [MailKit.Security.SecureSocketOptions] $SecureSocketOptions = [MailKit.Security.SecureSocketOptions]::Auto,

        [Parameter(ParameterSetName = 'SecureString')]

        [Parameter(ParameterSetName = 'oAuth')]
        [Parameter(ParameterSetName = 'Compatibility')]
        [switch] $UseSsl,

        [Parameter(ParameterSetName = 'SecureString')]

        [Parameter(ParameterSetName = 'oAuth')]
        [Parameter(ParameterSetName = 'Compatibility')]
        [switch] $SkipCertificateRevocation,

        [Parameter(ParameterSetName = 'SecureString')]

        [Parameter(ParameterSetName = 'oAuth')]
        [Parameter(ParameterSetName = 'Compatibility')]
        [switch] $SkipCertificateValidatation,

        [Parameter(ParameterSetName = 'SecureString')]

        [Parameter(ParameterSetName = 'oAuth')]
        [Parameter(ParameterSetName = 'Graph')]
        [Parameter(ParameterSetName = 'Compatibility')]
        [Parameter(ParameterSetName = 'SendGrid')]
        [alias('Body')][string[]] $HTML,

        [Parameter(ParameterSetName = 'SecureString')]

        [Parameter(ParameterSetName = 'oAuth')]
        [Parameter(ParameterSetName = 'Graph')]
        [Parameter(ParameterSetName = 'Compatibility')]
        [Parameter(ParameterSetName = 'SendGrid')]
        [string[]] $Text,

        [Parameter(ParameterSetName = 'SecureString')]

        [Parameter(ParameterSetName = 'oAuth')]
        [Parameter(ParameterSetName = 'Graph')]
        [Parameter(ParameterSetName = 'Compatibility')]
        [Parameter(ParameterSetName = 'SendGrid')]
        [alias('Attachments')][string[]] $Attachment,

        [Parameter(ParameterSetName = 'SecureString')]

        [Parameter(ParameterSetName = 'oAuth')]
        [Parameter(ParameterSetName = 'Compatibility')]
        [int] $Timeout = 12000,

        [Parameter(ParameterSetName = 'oAuth')]
        [alias('oAuth')][switch] $oAuth2,

        [Parameter(ParameterSetName = 'Graph')]
        [switch] $Graph,

        [Parameter(ParameterSetName = 'SecureString')]
        [switch] $AsSecureString,

        [Parameter(ParameterSetName = 'SendGrid')]
        [switch] $SendGrid,

        [Parameter(ParameterSetName = 'SendGrid')]
        [switch] $SeparateTo,

        [Parameter(ParameterSetName = 'Graph')]
        [switch] $DoNotSaveToSentItems,

        # Different feature set
        [Parameter(ParameterSetName = 'Grouped')]
        [alias('EmailParameters')][System.Collections.IDictionary] $Email,

        [Parameter(ParameterSetName = 'SecureString')]

        [Parameter(ParameterSetName = 'oAuth')]
        [Parameter(ParameterSetName = 'Compatibility')]
        [Parameter(ParameterSetName = 'Graph')]
        [Parameter(ParameterSetName = 'Grouped')]
        [Parameter(ParameterSetName = 'SendGrid')]
        [switch] $Suppress,

        [Parameter(ParameterSetName = 'SecureString')]
        [Parameter(ParameterSetName = 'oAuth')]
        [Parameter(ParameterSetName = 'Compatibility')]
        [string[]] $LogPath,

        [Parameter(ParameterSetName = 'SecureString')]
        [Parameter(ParameterSetName = 'oAuth')]
        [Parameter(ParameterSetName = 'Compatibility')]
        [switch] $LogTimestamps,

        [Parameter(ParameterSetName = 'SecureString')]
        [Parameter(ParameterSetName = 'oAuth')]
        [Parameter(ParameterSetName = 'Compatibility')]
        [string] $LogTimeStampsFormat = "yyyy-MM-dd HH:mm:ss:fff",

        [Parameter(ParameterSetName = 'SecureString')]
        [Parameter(ParameterSetName = 'oAuth')]
        [Parameter(ParameterSetName = 'Compatibility')]
        [switch] $LogSecrets,

        [Parameter(ParameterSetName = 'SecureString')]
        [Parameter(ParameterSetName = 'oAuth')]
        [Parameter(ParameterSetName = 'Compatibility')]
        [string] $LogClientPrefix,

        [Parameter(ParameterSetName = 'SecureString')]
        [Parameter(ParameterSetName = 'oAuth')]
        [Parameter(ParameterSetName = 'Compatibility')]
        [string] $LogServerPrefix
    )
    if ($Email) {
        # Following code makes sure both formats are accepted.
        if ($Email.EmailTo) {
            $EmailParameters = $Email.Clone()
        } else {
            $EmailParameters = @{
                EmailFrom                   = $Email.From
                EmailTo                     = $Email.To
                EmailCC                     = $Email.CC
                EmailBCC                    = $Email.BCC
                EmailReplyTo                = $Email.ReplyTo
                EmailServer                 = $Email.Server
                EmailServerPassword         = $Email.Password
                EmailServerPasswordAsSecure = $Email.PasswordAsSecure
                EmailServerPasswordFromFile = $Email.PasswordFromFile
                EmailServerPort             = $Email.Port
                EmailServerLogin            = $Email.Login
                EmailServerEnableSSL        = $Email.EnableSsl
                EmailEncoding               = $Email.Encoding
                EmailEncodingSubject        = $Email.EncodingSubject
                EmailEncodingBody           = $Email.EncodingBody
                EmailSubject                = $Email.Subject
                EmailPriority               = $Email.Priority
                EmailDeliveryNotifications  = $Email.DeliveryNotifications
                EmailUseDefaultCredentials  = $Email.UseDefaultCredentials
            }
        }
        $From = $EmailParameters.EmailFrom
        $To = $EmailParameters.EmailTo
        $Cc = $EmailParameters.EmailCC
        $Bcc = $EmailParameters.EmailBCC
        $ReplyTo = $EmailParameters.EmailReplyTo
        $Server = $EmailParameters.EmailServer
        $Password = $EmailParameters.EmailServerPassword
        # $EmailServerPasswordAsSecure = $EmailParameters.EmailServerPasswordAsSecure
        # $EmailServerPasswordFromFile = $EmailParameters.EmailServerPasswordFromFile
        $Port = $EmailParameters.EmailServerPort
        $Username = $EmailParameters.EmailServerLogin
        #$UseSsl = $EmailParameters.EmailServerEnableSSL
        $Encoding = $EmailParameters.EmailEncoding
        #$EncodingSubject = $EmailParameters.EmailEncodingSubject
        $Encoding = $EmailParameters.EmailEncodingBody
        $Subject = $EmailParameters.EmailSubject
        $Priority = $EmailParameters.EmailPriority
        $DeliveryNotificationOption = $EmailParameters.EmailDeliveryNotifications
        #$EmailUseDefaultCredentials = $EmailParameters.EmailUseDefaultCredentials

    } else {
        if ($null -eq $To -and $null -eq $Bcc -and $null -eq $Cc) {
            if ($PSBoundParameters.ErrorAction -eq 'Stop') {
                Write-Error 'At least one To, CC or BCC is required.'
                return
            } else {
                Write-Warning 'Send-EmailMessage - At least one To, CC or BCC is required.'
                return
            }
        }
    }

    # lets define credentials early on, because if it's Graph we use different way to send emails
    if ($Credential) {
        if ($oAuth2.IsPresent) {
            $Authorization = ConvertFrom-OAuth2Credential -Credential $Credential
            $SaslMechanismOAuth2 = [MailKit.Security.SaslMechanismOAuth2]::new($Authorization.UserName, $Authorization.Token)
            $SmtpCredentials = $Credential
        } elseif ($Graph.IsPresent) {
            # Sending email via Office 365 Graph
            $sendGraphMailMessageSplat = @{
                From                 = $From
                To                   = $To
                Cc                   = $CC
                Bcc                  = $Bcc
                Subject              = $Subject
                HTML                 = $HTML
                Text                 = $Text
                Attachment           = $Attachment
                Credential           = $Credential
                Priority             = $Priority
                ReplyTo              = $ReplyTo
                DoNotSaveToSentItems = $DoNotSaveToSentItems.IsPresent
            }
            Remove-EmptyValue -Hashtable $sendGraphMailMessageSplat
            return Send-GraphMailMessage @sendGraphMailMessageSplat
        } elseif ($SendGrid.IsPresent) {
            # Sending email via SendGrid
            $sendGraphMailMessageSplat = @{
                From       = $From
                To         = $To
                Cc         = $CC
                Bcc        = $Bcc
                Subject    = $Subject
                HTML       = $HTML
                Text       = $Text
                Attachment = $Attachment
                Credential = $Credential
                Priority   = $Priority
                ReplyTo    = $ReplyTo
                SeparateTo = $SeparateTo.IsPresent
            }
            Remove-EmptyValue -Hashtable $sendGraphMailMessageSplat
            return Send-SendGridMailMessage @sendGraphMailMessageSplat
        } else {
            $SmtpCredentials = $Credential
        }
    } elseif ($Username -and $Password -and $AsSecureString) {
        # Convert to SecureString
        try {
            $secStringPassword = ConvertTo-SecureString -ErrorAction Stop -String $Password
            $SmtpCredentials = [System.Management.Automation.PSCredential]::new($UserName, $secStringPassword)
        } catch {
            Write-Warning "Send-EmailMessage - Couldn't translate secure string to password. Error $($_.Exception.Message)"
            return
        }
    } elseif ($Username -and $Password) {
        #void Authenticate(string userName, string password, System.Threading.CancellationToken cancellationToken)
    }



    $Message = [MimeKit.MimeMessage]::new()

    # Doing translation for compatibility with Send-MailMessage
    if ($Priority -eq 'High') {
        $Message.Priority = [MimeKit.MessagePriority]::Urgent
    } elseif ($Priority -eq 'Low') {
        $Message.Priority = [MimeKit.MessagePriority]::NonUrgent
    } else {
        $Message.Priority = [MimeKit.MessagePriority]::Normal
    }

    [MimeKit.InternetAddress] $SmtpFrom = ConvertTo-MailboxAddress -MailboxAddress $From
    $Message.From.Add($SmtpFrom)

    if ($To) {
        [MimeKit.InternetAddress[]] $SmtpTo = ConvertTo-MailboxAddress -MailboxAddress $To
        $Message.To.AddRange($SmtpTo)
    }
    if ($Cc) {
        [MimeKit.InternetAddress[]] $SmtpCC = ConvertTo-MailboxAddress -MailboxAddress $Cc
        $Message.Cc.AddRange($SmtpCC)
    }
    if ($Bcc) {
        [MimeKit.InternetAddress[]] $SmtpBcc = ConvertTo-MailboxAddress -MailboxAddress $Bcc
        $Message.Bcc.AddRange($SmtpBcc)
    }
    if ($ReplyTo) {
        [MimeKit.InternetAddress] $SmtpReplyTo = ConvertTo-MailboxAddress -MailboxAddress $ReplyTo
        $Message.ReplyTo.Add($SmtpReplyTo)
    }
    $MailSentTo = -join ($To -join ',', $CC -join ', ', $Bcc -join ', ')
    if ($Subject) {
        $Message.Subject = $Subject
    }

    [System.Text.Encoding] $SmtpEncoding = [System.Text.Encoding]::$Encoding

    $BodyBuilder = [MimeKit.BodyBuilder]::new()
    if ($HTML) {
        $BodyBuilder.HtmlBody = $HTML
    }
    if ($Text) {
        $BodyBuilder.TextBody = $Text
    }
    if ($Attachment) {
        foreach ($A in $Attachment) {
            $null = $BodyBuilder.Attachments.Add($A)
        }
    }
    $Message.Body = $BodyBuilder.ToMessageBody()

    ### SMTP Part Below

    if ($LogPath) {
        $ProtocolLogger = [MailKit.ProtocolLogger]::new($LogPath)
        $ProtocolLogger.LogTimestamps = $LogTimestamps.IsPresent
        $ProtocolLogger.RedactSecrets = -not $LogSecrets.IsPresent
        if ($LogTimeStampsFormat) {
            $ProtocolLogger.TimestampFormat = $LogTimeStampsFormat
        }
        if ($PSBoundParameters.Keys.Contains('LogServerPrefix')) {
            $ProtocolLogger.ServerPrefix = $LogServerPrefix
        }
        if ($PSBoundParameters.Keys.Contains('LogClientPrefix')) {
            $ProtocolLogger.ClientPrefix = $LogClientPrefix
        }
        $SmtpClient = [MySmtpClientWithLogger]::new($ProtocolLogger)
    } else {
        $SmtpClient = [MySmtpClient]::new()
    }

    if ($SkipCertificateRevocation) {
        $SmtpClient.CheckCertificateRevocation = $false
    }
    if ($SkipCertificateValidatation) {
        $CertificateCallback = [Net.ServicePointManager]::ServerCertificateValidationCallback
        [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        #$SmtpClient.ServerCertificateValidationCallback = [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    }
    if ($DeliveryNotificationOption) {
        # This requires custom class MySmtpClient
        $SmtpClient.DeliveryNotificationOption = $DeliveryNotificationOption
    }
    if ($DeliveryStatusNotificationType) {
        $SmtpClient.DeliveryStatusNotificationType = $DeliveryStatusNotificationType
    }
    if ($UseSsl) {
        # By default Auto is used, but if someone wants UseSSL that's fine too
        $SecureSocketOptions = [MailKit.Security.SecureSocketOptions]::StartTls
    }
    try {
        $SmtpClient.Connect($Server, $Port, $SecureSocketOptions)
        # Assign back certificate callback
        [Net.ServicePointManager]::ServerCertificateValidationCallback = $CertificateCallback
    } catch {
        # Assign back certificate callback
        [Net.ServicePointManager]::ServerCertificateValidationCallback = $CertificateCallback

        if ($PSBoundParameters.ErrorAction -eq 'Stop') {
            Write-Error $_
            return
        } else {
            Write-Warning "Send-EmailMessage - Error: $($_.Exception.Message)"
            Write-Warning "Send-EmailMessage - Possible issue: Port? ($Port was used), Using SSL? ($SecureSocketOptions was used). You can also try SkipCertificateValidation or SkipCertificateRevocation. "
            if (-not $Suppress) {
                return [PSCustomObject] @{
                    Status = $False
                    Error  = $($_.Exception.Message)
                    SentTo = $MailSentTo
                }
            }
        }
    }
    if ($SmtpCredentials) {
        if ($oAuth2.IsPresent) {
            try {
                $SmtpClient.Authenticate($SaslMechanismOAuth2)
            } catch {
                if ($PSBoundParameters.ErrorAction -eq 'Stop') {
                    Write-Error $_
                    return
                } else {
                    Write-Warning "Send-EmailMessage - Error: $($_.Exception.Message)"
                    if (-not $Suppress) {
                        return [PSCustomObject] @{
                            Status = $False
                            Error  = $($_.Exception.Message)
                            SentTo = $MailSentTo
                        }
                    }
                }
            }
        } elseif ($Graph.IsPresent) {
            # This is not going to happen is graph is used
        } else {
            try {
                $SmtpClient.Authenticate($SmtpEncoding, $SmtpCredentials, [System.Threading.CancellationToken]::None)
            } catch {
                if ($PSBoundParameters.ErrorAction -eq 'Stop') {
                    Write-Error $_
                    return
                } else {
                    Write-Warning "Send-EmailMessage - Error: $($_.Exception.Message)"
                    if (-not $Suppress) {
                        return [PSCustomObject] @{
                            Status = $False
                            Error  = $($_.Exception.Message)
                            SentTo = $MailSentTo
                        }
                    }
                }
            }
        }
    } elseif ($UserName -and $Password) {
        try {
            $SmtpClient.Authenticate($UserName, $Password, [System.Threading.CancellationToken]::None)
        } catch {
            if ($PSBoundParameters.ErrorAction -eq 'Stop') {
                Write-Error $_
                return
            } else {
                Write-Warning "Send-EmailMessage - Error: $($_.Exception.Message)"
                if (-not $Suppress) {
                    return [PSCustomObject] @{
                        Status = $False
                        Error  = $($_.Exception.Message)
                        SentTo = $MailSentTo
                    }
                }
            }
        }
    }
    $SmtpClient.Timeout = $Timeout
    try {
        if ($PSCmdlet.ShouldProcess("$MailSentTo", 'Send-EmailMessage')) {
            $SmtpClient.Send($Message)
            if (-not $Suppress) {
                [PSCustomObject] @{
                    Status = $True
                    Error  = ''
                    SentTo = $MailSentTo
                }
            }
        } else {
            if (-not $Suppress) {
                [PSCustomObject] @{
                    Status = $false
                    Error  = 'Email not sent (WhatIf)'
                    SentTo = $MailSentTo
                }
            }
        }
    } catch {
        if ($PSBoundParameters.ErrorAction -eq 'Stop') {
            Write-Error $_
            return
        } else {
            Write-Warning "Send-EmailMessage - Error: $($_.Exception.Message)"
        }
        if (-not $Suppress) {
            [PSCustomObject] @{
                Status = $False
                Error  = $($_.Exception.Message)
                SentTo = $MailSentTo
            }
        }
    }
    $SmtpClient.Disconnect($true)
}
function Test-EmailAddress {
    <#
    .SYNOPSIS
    Checks if email address matches conditions to be valid email address.

    .DESCRIPTION
    Checks if email address matches conditions to be valid email address.

    .PARAMETER EmailAddress
    EmailAddress to check

    .EXAMPLE
    Test-EmailAddress -EmailAddress 'przemyslaw.klys@test'

    .EXAMPLE
    Test-EmailAddress -EmailAddress 'przemyslaw.klys@test.pl'

    .EXAMPLE
    Test-EmailAddress -EmailAddress 'przemyslaw.klys@test','przemyslaw.klys@test.pl'

    .NOTES
    General notes
    #>
    [cmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ValueFromPipeline, Position = 0)][string[]] $EmailAddress
    )
    process {
        foreach ($Email in $EmailAddress) {
            [PSCustomObject] @{
                EmailAddress = $Email
                IsValid      = [EmailValidation.EmailValidator]::Validate($Email)
            }
        }
    }
}




# Export functions and aliases as required
Export-ModuleMember -Function @('Connect-IMAP', 'Connect-oAuthGoogle', 'Connect-oAuthO365', 'Connect-POP', 'ConvertTo-GraphCredential', 'ConvertTo-OAuth2Credential', 'ConvertTo-SendGridCredential', 'Disconnect-IMAP', 'Disconnect-POP', 'Find-DKIMRecord', 'Find-DMARCRecord', 'Find-DNSBL', 'Find-MxRecord', 'Find-SPFRecord', 'Get-IMAPFolder', 'Get-IMAPMessage', 'Get-MailFolder', 'Get-MailMessage', 'Get-POPMessage', 'Resolve-DnsQuery', 'Resolve-DnsQueryRest', 'Save-MailMessage', 'Save-POPMessage', 'Send-EmailMessage', 'Test-EmailAddress') -Alias @('Connect-POP3', 'Disconnect-POP3', 'Find-BlackList', 'Find-BlockList', 'Get-POP3Message', 'Save-POP3Message')
# SIG # Begin signature block
# MIIdWQYJKoZIhvcNAQcCoIIdSjCCHUYCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUDwcuIuQZqFbTzkkhMieL9BED
# SGGgghhnMIIDtzCCAp+gAwIBAgIQDOfg5RfYRv6P5WD8G/AwOTANBgkqhkiG9w0B
# AQUFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVk
# IElEIFJvb3QgQ0EwHhcNMDYxMTEwMDAwMDAwWhcNMzExMTEwMDAwMDAwWjBlMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3Qg
# Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtDhXO5EOAXLGH87dg
# +XESpa7cJpSIqvTO9SA5KFhgDPiA2qkVlTJhPLWxKISKityfCgyDF3qPkKyK53lT
# XDGEKvYPmDI2dsze3Tyoou9q+yHyUmHfnyDXH+Kx2f4YZNISW1/5WBg1vEfNoTb5
# a3/UsDg+wRvDjDPZ2C8Y/igPs6eD1sNuRMBhNZYW/lmci3Zt1/GiSw0r/wty2p5g
# 0I6QNcZ4VYcgoc/lbQrISXwxmDNsIumH0DJaoroTghHtORedmTpyoeb6pNnVFzF1
# roV9Iq4/AUaG9ih5yLHa5FcXxH4cDrC0kqZWs72yl+2qp/C3xag/lRbQ/6GW6whf
# GHdPAgMBAAGjYzBhMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0G
# A1UdDgQWBBRF66Kv9JLLgjEtUYunpyGd823IDzAfBgNVHSMEGDAWgBRF66Kv9JLL
# gjEtUYunpyGd823IDzANBgkqhkiG9w0BAQUFAAOCAQEAog683+Lt8ONyc3pklL/3
# cmbYMuRCdWKuh+vy1dneVrOfzM4UKLkNl2BcEkxY5NM9g0lFWJc1aRqoR+pWxnmr
# EthngYTffwk8lOa4JiwgvT2zKIn3X/8i4peEH+ll74fg38FnSbNd67IJKusm7Xi+
# fT8r87cmNW1fiQG2SVufAQWbqz0lwcy2f8Lxb4bG+mRo64EtlOtCt/qMHt1i8b5Q
# Z7dsvfPxH2sMNgcWfzd8qVttevESRmCD1ycEvkvOl77DZypoEd+A5wwzZr8TDRRu
# 838fYxAe+o0bJW1sj6W3YQGx0qMmoRBxna3iw/nDmVG3KwcIzi7mULKn+gpFL6Lw
# 8jCCBP4wggPmoAMCAQICEA1CSuC+Ooj/YEAhzhQA8N0wDQYJKoZIhvcNAQELBQAw
# cjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTExMC8GA1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVk
# IElEIFRpbWVzdGFtcGluZyBDQTAeFw0yMTAxMDEwMDAwMDBaFw0zMTAxMDYwMDAw
# MDBaMEgxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjEgMB4G
# A1UEAxMXRGlnaUNlcnQgVGltZXN0YW1wIDIwMjEwggEiMA0GCSqGSIb3DQEBAQUA
# A4IBDwAwggEKAoIBAQDC5mGEZ8WK9Q0IpEXKY2tR1zoRQr0KdXVNlLQMULUmEP4d
# yG+RawyW5xpcSO9E5b+bYc0VkWJauP9nC5xj/TZqgfop+N0rcIXeAhjzeG28ffnH
# bQk9vmp2h+mKvfiEXR52yeTGdnY6U9HR01o2j8aj4S8bOrdh1nPsTm0zinxdRS1L
# sVDmQTo3VobckyON91Al6GTm3dOPL1e1hyDrDo4s1SPa9E14RuMDgzEpSlwMMYpK
# jIjF9zBa+RSvFV9sQ0kJ/SYjU/aNY+gaq1uxHTDCm2mCtNv8VlS8H6GHq756Wwog
# L0sJyZWnjbL61mOLTqVyHO6fegFz+BnW/g1JhL0BAgMBAAGjggG4MIIBtDAOBgNV
# HQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcD
# CDBBBgNVHSAEOjA4MDYGCWCGSAGG/WwHATApMCcGCCsGAQUFBwIBFhtodHRwOi8v
# d3d3LmRpZ2ljZXJ0LmNvbS9DUFMwHwYDVR0jBBgwFoAU9LbhIB3+Ka7S5GGlsqIl
# ssgXNW4wHQYDVR0OBBYEFDZEho6kurBmvrwoLR1ENt3janq8MHEGA1UdHwRqMGgw
# MqAwoC6GLGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9zaGEyLWFzc3VyZWQtdHMu
# Y3JsMDKgMKAuhixodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vc2hhMi1hc3N1cmVk
# LXRzLmNybDCBhQYIKwYBBQUHAQEEeTB3MCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz
# cC5kaWdpY2VydC5jb20wTwYIKwYBBQUHMAKGQ2h0dHA6Ly9jYWNlcnRzLmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydFNIQTJBc3N1cmVkSURUaW1lc3RhbXBpbmdDQS5jcnQw
# DQYJKoZIhvcNAQELBQADggEBAEgc3LXpmiO85xrnIA6OZ0b9QnJRdAojR6OrktIl
# xHBZvhSg5SeBpU0UFRkHefDRBMOG2Tu9/kQCZk3taaQP9rhwz2Lo9VFKeHk2eie3
# 8+dSn5On7UOee+e03UEiifuHokYDTvz0/rdkd2NfI1Jpg4L6GlPtkMyNoRdzDfTz
# ZTlwS/Oc1np72gy8PTLQG8v1Yfx1CAB2vIEO+MDhXM/EEXLnG2RJ2CKadRVC9S0y
# OIHa9GCiurRS+1zgYSQlT7LfySmoc0NR2r1j1h9bm/cuG08THfdKDXF+l7f0P4Tr
# weOjSaH6zqe/Vs+6WXZhiV9+p7SOZ3j5NpjhyyjaW4emii8wggUwMIIEGKADAgEC
# AhAECRgbX9W7ZnVTQ7VvlVAIMA0GCSqGSIb3DQEBCwUAMGUxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
# b20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0xMzEw
# MjIxMjAwMDBaFw0yODEwMjIxMjAwMDBaMHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNV
# BAMTKERpZ2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBDb2RlIFNpZ25pbmcgQ0EwggEi
# MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD407Mcfw4Rr2d3B9MLMUkZz9D7
# RZmxOttE9X/lqJ3bMtdx6nadBS63j/qSQ8Cl+YnUNxnXtqrwnIal2CWsDnkoOn7p
# 0WfTxvspJ8fTeyOU5JEjlpB3gvmhhCNmElQzUHSxKCa7JGnCwlLyFGeKiUXULaGj
# 6YgsIJWuHEqHCN8M9eJNYBi+qsSyrnAxZjNxPqxwoqvOf+l8y5Kh5TsxHM/q8grk
# V7tKtel05iv+bMt+dDk2DZDv5LVOpKnqagqrhPOsZ061xPeM0SAlI+sIZD5SlsHy
# DxL0xY4PwaLoLFH3c7y9hbFig3NBggfkOItqcyDQD2RzPJ6fpjOp/RnfJZPRAgMB
# AAGjggHNMIIByTASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAT
# BgNVHSUEDDAKBggrBgEFBQcDAzB5BggrBgEFBQcBAQRtMGswJAYIKwYBBQUHMAGG
# GGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0cDovL2Nh
# Y2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNydDCB
# gQYDVR0fBHoweDA6oDigNoY0aHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0QXNzdXJlZElEUm9vdENBLmNybDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDBPBgNVHSAESDBGMDgG
# CmCGSAGG/WwAAgQwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQu
# Y29tL0NQUzAKBghghkgBhv1sAzAdBgNVHQ4EFgQUWsS5eyoKo6XqcQPAYPkt9mV1
# DlgwHwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8wDQYJKoZIhvcNAQEL
# BQADggEBAD7sDVoks/Mi0RXILHwlKXaoHV0cLToaxO8wYdd+C2D9wz0PxK+L/e8q
# 3yBVN7Dh9tGSdQ9RtG6ljlriXiSBThCk7j9xjmMOE0ut119EefM2FAaK95xGTlz/
# kLEbBw6RFfu6r7VRwo0kriTGxycqoSkoGjpxKAI8LpGjwCUR4pwUR6F6aGivm6dc
# IFzZcbEMj7uo+MUSaJ/PQMtARKUT8OZkDCUIQjKyNookAv4vcn4c10lFluhZHen6
# dGRrsutmQ9qzsIzV6Q3d9gEgzpkxYz0IGhizgZtPxpMQBvwHgfqL2vmCSfdibqFT
# +hKUGIUukpHqaGxEMrJmoecYpJpkUe8wggUxMIIEGaADAgECAhAKoSXW1jIbfkHk
# Bdo2l8IVMA0GCSqGSIb3DQEBCwUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxE
# aWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMT
# G0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0xNjAxMDcxMjAwMDBaFw0z
# MTAxMDcxMjAwMDBaMHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJ
# bmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNVBAMTKERpZ2lDZXJ0
# IFNIQTIgQXNzdXJlZCBJRCBUaW1lc3RhbXBpbmcgQ0EwggEiMA0GCSqGSIb3DQEB
# AQUAA4IBDwAwggEKAoIBAQC90DLuS82Pf92puoKZxTlUKFe2I0rEDgdFM1EQfdD5
# fU1ofue2oPSNs4jkl79jIZCYvxO8V9PD4X4I1moUADj3Lh477sym9jJZ/l9lP+Cb
# 6+NGRwYaVX4LJ37AovWg4N4iPw7/fpX786O6Ij4YrBHk8JkDbTuFfAnT7l3ImgtU
# 46gJcWvgzyIQD3XPcXJOCq3fQDpct1HhoXkUxk0kIzBdvOw8YGqsLwfM/fDqR9mI
# UF79Zm5WYScpiYRR5oLnRlD9lCosp+R1PrqYD4R/nzEU1q3V8mTLex4F0IQZchfx
# FwbvPc3WTe8GQv2iUypPhR3EHTyvz9qsEPXdrKzpVv+TAgMBAAGjggHOMIIByjAd
# BgNVHQ4EFgQU9LbhIB3+Ka7S5GGlsqIlssgXNW4wHwYDVR0jBBgwFoAUReuir/SS
# y4IxLVGLp6chnfNtyA8wEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMC
# AYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUF
# BzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6
# Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5j
# cnQwgYEGA1UdHwR6MHgwOqA4oDaGNGh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9E
# aWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRp
# Z2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwUAYDVR0gBEkw
# RzA4BgpghkgBhv1sAAIEMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2lj
# ZXJ0LmNvbS9DUFMwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4IBAQBxlRLp
# UYdWac3v3dp8qmN6s3jPBjdAhO9LhL/KzwMC/cWnww4gQiyvd/MrHwwhWiq3BTQd
# aq6Z+CeiZr8JqmDfdqQ6kw/4stHYfBli6F6CJR7Euhx7LCHi1lssFDVDBGiy23UC
# 4HLHmNY8ZOUfSBAYX4k4YU1iRiSHY4yRUiyvKYnleB/WCxSlgNcSR3CzddWThZN+
# tpJn+1Nhiaj1a5bA9FhpDXzIAbG5KHW3mWOFIoxhynmUfln8jA/jb7UBJrZspe6H
# USHkWGCbugwtK22ixH67xCUrRwIIfEmuE7bhfEJCKMYYVs9BNLZmXbZ0e/VWMyIv
# IjayS6JKldj1po5SMIIFPTCCBCWgAwIBAgIQBNXcH0jqydhSALrNmpsqpzANBgkq
# hkiG9w0BAQsFADByMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5j
# MRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBT
# SEEyIEFzc3VyZWQgSUQgQ29kZSBTaWduaW5nIENBMB4XDTIwMDYyNjAwMDAwMFoX
# DTIzMDcwNzEyMDAwMFowejELMAkGA1UEBhMCUEwxEjAQBgNVBAgMCcWabMSFc2tp
# ZTERMA8GA1UEBxMIS2F0b3dpY2UxITAfBgNVBAoMGFByemVteXPFgmF3IEvFgnlz
# IEVWT1RFQzEhMB8GA1UEAwwYUHJ6ZW15c8WCYXcgS8WCeXMgRVZPVEVDMIIBIjAN
# BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv7KB3iyBrhkLUbbFe9qxhKKPBYqD
# Bqlnr3AtpZplkiVjpi9dMZCchSeT5ODsShPuZCIxJp5I86uf8ibo3vi2S9F9AlfF
# jVye3dTz/9TmCuGH8JQt13ozf9niHecwKrstDVhVprgxi5v0XxY51c7zgMA2g1Ub
# +3tii0vi/OpmKXdL2keNqJ2neQ5cYly/GsI8CREUEq9SZijbdA8VrRF3SoDdsWGf
# 3tZZzO6nWn3TLYKQ5/bw5U445u/V80QSoykszHRivTj+H4s8ABiforhi0i76beA6
# Ea41zcH4zJuAp48B4UhjgRDNuq8IzLWK4dlvqrqCBHKqsnrF6BmBrv+BXQIDAQAB
# o4IBxTCCAcEwHwYDVR0jBBgwFoAUWsS5eyoKo6XqcQPAYPkt9mV1DlgwHQYDVR0O
# BBYEFBixNSfoHFAgJk4JkDQLFLRNlJRmMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE
# DDAKBggrBgEFBQcDAzB3BgNVHR8EcDBuMDWgM6Axhi9odHRwOi8vY3JsMy5kaWdp
# Y2VydC5jb20vc2hhMi1hc3N1cmVkLWNzLWcxLmNybDA1oDOgMYYvaHR0cDovL2Ny
# bDQuZGlnaWNlcnQuY29tL3NoYTItYXNzdXJlZC1jcy1nMS5jcmwwTAYDVR0gBEUw
# QzA3BglghkgBhv1sAwEwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNl
# cnQuY29tL0NQUzAIBgZngQwBBAEwgYQGCCsGAQUFBwEBBHgwdjAkBggrBgEFBQcw
# AYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tME4GCCsGAQUFBzAChkJodHRwOi8v
# Y2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRTSEEyQXNzdXJlZElEQ29kZVNp
# Z25pbmdDQS5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAmr1s
# z4lsLARi4wG1eg0B8fVJFowtect7SnJUrp6XRnUG0/GI1wXiLIeow1UPiI6uDMsR
# XPHUF/+xjJw8SfIbwava2eXu7UoZKNh6dfgshcJmo0QNAJ5PIyy02/3fXjbUREHI
# NrTCvPVbPmV6kx4Kpd7KJrCo7ED18H/XTqWJHXa8va3MYLrbJetXpaEPpb6zk+l8
# Rj9yG4jBVRhenUBUUj3CLaWDSBpOA/+sx8/XB9W9opYfYGb+1TmbCkhUg7TB3gD6
# o6ESJre+fcnZnPVAPESmstwsT17caZ0bn7zETKlNHbc1q+Em9kyBjaQRcEQoQQNp
# ezQug9ufqExx6lHYDjGCBFwwggRYAgEBMIGGMHIxCzAJBgNVBAYTAlVTMRUwEwYD
# VQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAv
# BgNVBAMTKERpZ2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBDb2RlIFNpZ25pbmcgQ0EC
# EATV3B9I6snYUgC6zZqbKqcwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwxCjAI
# oAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIB
# CzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFGxzVWOJ4Du8/rsjfBIP
# +Giy9NYoMA0GCSqGSIb3DQEBAQUABIIBAGMO9f2WQi4QXf5mSoKVR0rN1cXdAchW
# HdDqaFd75uQIT14+LDFIHOMDhEHyuOLaLAuLAU3uCgzIlfy2brb4dT6EVTcJBY+a
# LklGkjM0i9C2akkqdvx7Y6E/xu6HHfhhzVLDzMfLxHpe8/jvAVA+HK5eznJYeRQy
# ZJBx9TCWDohzMKOLIoJP81UloRCgKoWAKvIZoibYK3yfWWPuFuETWkEVvfrHlyB6
# hZ4hy3Hc0Fsya9XnYmJIW6yyHEBf4XPptiACxBrz2Bf8bgOpZI8Qpo6Ab5qmFSz2
# /K+0zUk400Q0titT3O3md0bEVDCAElgz8bk5BWA4RxD+zzyFU/5OHNShggIwMIIC
# LAYJKoZIhvcNAQkGMYICHTCCAhkCAQEwgYYwcjELMAkGA1UEBhMCVVMxFTATBgNV
# BAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTExMC8G
# A1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIFRpbWVzdGFtcGluZyBDQQIQ
# DUJK4L46iP9gQCHOFADw3TANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzEL
# BgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIyMDEwNzA4MTY1MlowLwYJKoZI
# hvcNAQkEMSIEIP8LFmQxRCZKpRNCpoLsgspXYbIGySV9QMM7ADECXdcEMA0GCSqG
# SIb3DQEBAQUABIIBAKfNzj2Zv0tPGwuO1NTG72k56W4/Tx4aQr8r03EZMwXxhsp/
# JJNuzRQLFqDUCZk7SLWyyc7ks1sfA96D+OzIqvwPOLM5iW/D3svcTVbDPJj07J63
# oO1Mip7b/f7jVVPCxnx7/3p2/nHdMl9Pxe8iAQ2BYSHFbLD5/Cb7wt0fUeID6cIi
# El5K16/p6KNFTJg1M4NtIq/BPfX/xLoDSuZB0j5VS4ZnbegVAiaRWE21r2neNIzO
# TwoV6q3mCMZNypUS4SkSasQ8Uny+DUYX/FRYynhybG1Iyy7j/CcS2WeD1FFBBZ3o
# hN1ShlZaeA1+x82KoBxLi6MxbfXwcqWOecTCxOQ=
# SIG # End signature block
