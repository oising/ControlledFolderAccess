#requires -module Defender

# Since we require Defender module, this is a Windows PowerShell only module.
[cmdletbinding()]
param()

function Get-AllowedApplication {
    [CmdletBinding()]
    param([string]$Name)

    $apps = @((Get-MpPreference).ControlledFolderAccessAllowedApplications)
    $filtered = @()

    # filter by Name ()
    if ($Name) {
        # wildcard filter not matching should never be an error
        if ([WildcardPattern]::ContainsWildcardCharacters($Name)) {
            $filtered = $($apps | where-object { $_ -like $Name })
        }
        else {
            # non-wildcarded filter returning nothing should throw error
            if ($apps -notcontains $Name) {
                Write-Error "$Name is not in the list of allowed applications."
            }
            else {
                $filtered += $Name
            } 
        }
    }
    else {
        $filtered = $apps
    }
    $filtered
}

function Test-AllowedApplication {
    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [Alias("PSPath")]
        [Parameter(Position = 0, ValueFromPipelineByPropertyName = $true)]
        [string]$AppPath
    )

    (Get-MpPreference).ControlledFolderAccessAllowedApplications -contains $appPath
}

function Test-ControlledFolder {
    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [Alias("PSPath")]
        [Parameter(Position = 0, ValueFromPipelineByPropertyName = $true)]
        [string]$FolderPath
    )

    if ((test-path -LiteralPath $folderPath)) {
        (Get-MpPreference).ControlledFolderAccessProtectedFolders -contains $folderPath
    }
    else {
        Write-Warning "$folderPath does not exist."
        return $false
    }
}

# Get-MpPreference | select -exp ControlledFolderAccessAllowedApplications | % { Get-AuthenticodeSignature -FilePath $_ }

$SCRIPT:authsigCache = @{}
$SCRIPT:query = @"
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Windows Defender/Operational">
    <Select Path="Microsoft-Windows-Windows Defender/Operational">*[System[(EventID=1123)]]</Select>
  </Query>
</QueryList>
"@

function Get-BlockedApplication {
    [cmdletbinding()]
    param(
        [parameter(position=0)]
        [Alias("PSPath", "FilePath")]
        [string]$Name
    )

    $prefs = Get-MpPreference
    $allowed = $prefs.ControlledFolderAccessAllowedApplications

    Get-WinEvent -FilterXml $query | ForEach-Object {
        $message = $_.message

        $process = [regex]::Match($message, 'Process Name: (.+)').groups[1].value
        $path = [regex]::Match($message, 'Path: ([^\n]+)').groups[1].value
        $user = [regex]::Match($message, 'User: (.+)').groups[1].value
    
        if ($allowed -notcontains $process) {
            [PSCustomObject]@{
                User    = $User
                Path    = [System.Environment]::ExpandEnvironmentVariables($Path).trim()
                Process = [System.Environment]::ExpandEnvironmentVariables($process).trim()
            } | ForEach-Object {
                
                $key = $_.process

                # cache authenticode signatures as computing hashes is costly
                if ($authsigCache[$key] -eq $null) {
                    if (test-path "$key") {
                        $authsigCache[$key] = Get-AuthenticodeSignature -FilePath $key
                    }
                    else {
                        write-warning "$key Does not exist"
                    }
                }
                else {
                    Write-Verbose "authenticode sig cache hit"
                }
    
                $_ | Add-Member -MemberType NoteProperty -Name ExecutableSigned -Value $authsigCache[$_.process].status -PassThru | `
                    add-member -MemberType NoteProperty -Name IsOSBinary -Value $authsigCache[$_.process].IsOSBinary -PassThru
            }
        } else {
            write-verbose "$process already in allowed list."
        }
    }
}

function Get-ProtectedFolder {
    [cmdletbinding()]
    param(
        [parameter(position=0, ValueFromPipelineByPropertyName=$true)]
        [Alias("PSPath")]
        [string]$Name
    )

    # TODO: filtering by $Name
    (Get-MpPreference).ControlledFolderAccessProtectedFolders
}

function Add-ProtectedFolder {}
function Remove-ProtectedFolder {}

function Add-AllowedApplication {
    [cmdletbinding()]
    param(
        [Parameter(position=0, ValueFromPipelineByPropertyName=$true)]
        [Alias("PSPath")]
        [string]$FilePath
    )

    if (-not(test-path $FilePath)) {
        Write-Error "File $FilePath does not exist."
    } else {
        $allowed = (Get-MpPreference).ControlledFolderAccessAllowedApplications
        $allowed += $FilePath

        Set-MpPreference -ControlledFolderAccessAllowedApplications $allowed
    }
}

function Remove-AllowedApplication {}


#
# 
#

if ((Get-MpPreference).EnableControlledFolderAccess -ne 1) {
    Write-Warning "Controlled Folder Access is currently not enabled."
}

# learn mode
# only allow IsOS files to be auto-accepted
# prompt for signed files
# require command line override -IncludeUnsignedExecutables (?)

Get-BlockedApplication



<#

wait until event
{
    if (file is Signed)
        # prompt 
    elseif (file is OSBinary)
        # auto-add
    else 
        # not signed, not os-binary 
}

#>