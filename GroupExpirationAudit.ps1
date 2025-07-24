
<#PSScriptInfo

.VERSION 1.0

.GUID 79d1df22-ec96-4860-b2d4-40dafb649ae1

.AUTHOR timmcmic

.COMPANYNAME

Micorosft CSS

.COPYRIGHT

.TAGS

.LICENSEURI

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES


.PRIVATEDATA

#>

#Requires -Module @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.29.1' } 
#Requires -Module @{ ModuleName = 'Microsoft.Graph.Groups'; ModuleVersion = '2.29.1' }
#Requires -Module @{ ModuleName = 'PSWriteHTML'; ModuleVersion = '1.30.8' }
<# 

.DESCRIPTION 
 This script audits group expiration and provides output information 

#> 
Param(
    #Define Microsoft Graph Parameters
        [Parameter(Mandatory = $false)]
        [ValidateSet("China","Global","USGov","USGovDod")]
        [string]$msGraphEnvironmentName="Global",
        [Parameter(Mandatory=$true)]
        [string]$msGraphTenantID="",
        [Parameter(Mandatory=$false)]
        [string]$msGraphApplicationID="",
        [Parameter(Mandatory=$false)]
        [string]$msGraphCertificateThumbprint="",
        [Parameter(Mandatory=$false)]
        [string]$msGraphClientSecret="",
        #Define other mandatory parameters
        [Parameter(Mandatory = $true)]
        [string]$logFolderPath
)

#*****************************************************
Function new-LogFile
{
    [cmdletbinding()]

    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$logFileName,
        [Parameter(Mandatory = $true)]
        [string]$logFolderPath
    )

    [string]$logFileSuffix=".log"
    [string]$fileName=$logFileName+$logFileSuffix

    # Get our log file path

    $logFolderPath = $logFolderPath+"\"+$logFileName+"\"
    
    #Since $logFile is defined in the calling function - this sets the log file name for the entire script
    
    $global:LogFile = Join-path $logFolderPath $fileName

    #Test the path to see if this exists if not create.

    [boolean]$pathExists = Test-Path -Path $logFolderPath

    if ($pathExists -eq $false)
    {
        try 
        {
            #Path did not exist - Creating

            New-Item -Path $logFolderPath -Type Directory
        }
        catch 
        {
            throw $_
        } 
    }
}

#*****************************************************
Function Out-LogFile
{
    [cmdletbinding()]

    Param
    (
        [Parameter(Mandatory = $true)]
        $String,
        [Parameter(Mandatory = $false)]
        [boolean]$isError=$FALSE
    )

    # Get the current date

    [string]$date = Get-Date -Format G

    # Build output string
    #In this case since I abuse the function to write data to screen and record it in log file
    #If the input is not a string type do not time it just throw it to the log.

    if ($string.gettype().name -eq "String")
    {
        [string]$logstring = ( "[" + $date + "] - " + $string)
    }
    else 
    {
        $logString = $String
    }

    # Write everything to our log file and the screen

    $logstring | Out-File -FilePath $global:LogFile -Append

    #Write to the screen the information passed to the log.

    if ($string.gettype().name -eq "String")
    {
        Write-Host $logString
    }
    else 
    {
        write-host $logString | select-object -expandProperty *
    }

    #If the output to the log is terminating exception - throw the same string.

    if ($isError -eq $TRUE)
    {
        #Ok - so here's the deal.
        #By default error action is continue.  IN all my function calls I use STOP for the most part.
        #In this case if we hit this error code - one of two things happen.
        #If the call is from another function that is not in a do while - the error is logged and we continue with exiting.
        #If the call is from a function in a do while - write-error rethrows the exception.  The exception is caught by the caller where a retry occurs.
        #This is how we end up logging an error then looping back around.

        if ($global:GraphConnection -eq $TRUE)
        {
            Disconnect-MGGraph
        }

        write-error $logString

        exit
    }
}

#*****************************************************
Function Validate-GraphInfo
{
    [cmdletbinding()]

    Param
    (
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$msGraphApplicationID,
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$msGraphCertificateThumbprint,
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$msGraphClientSecret
    )

    $functionConnectionType = ""
    $functionConnectionTypeInteractive = "Interactive"
    $functionConnectionTypeCertificate = "CertAuth"
    $functionConnectionTypeSecret = "ClientSecret"

    out-logfile -string "Entering Validate-GraphInfo"

    out-logfile -string "Testing parameters to determine graph authentication type."

    if (($msGraphApplicationID -eq "") -and ($msGraphCertificateThumbprint -eq "") -and ($msGraphClientSecret -eq ""))
    {
        out-logfile -string "No appID, certThumbprint, or clientSecret provided - set type interactive auth."
        $functionConnectionType = $functionConnectionTypeInteractive
    }
    elseif (($msGraphCertificateThumbprint -ne "") -and ($msGraphClientSecret -ne ""))
    {
        out-logfile -string "Specifying a certificate thumbprint and client secret is not allowed - specify one authentication method." -isError:$true
    }
    elseif ((($msGraphCertificateThumbprint -ne "") -or ($msGraphClientSecret -ne "")) -and ($msGraphApplicationID -eq ""))
    {
        out-logfile -string "Specifying a client secret or certificate thumbprint without application ID is not allowed - specify an application ID." -isError:$true
    }
    elseif ($msGraphApplicationID -ne "")
    {
        out-logfile -string "Application ID specified - check for certificate or client secret authentication."

        if ($msGraphCertificateThumbprint -ne "")
        {
            out-logfile -string "Application ID specifeid - certificate thumbprint specified - set type certificate auth."

            $functionConnectionType = $functionConnectionTypeCertificate
        }
        elseif ($msGraphClientSecret -ne "")
        {
            out-logfile -string "Application ID specifeid - client secret specified - set type client secret auth."

            $functionConnectionType = $functionConnectionTypeSecret
        }
        else 
        {
            out-logfile -string "Specifying an application ID without certificate thumbprint or client secret is not allowed - specify a certificate thumbprint or client secret." -isError:$true
        }
    }

    out-logfile -string "Exit Validate-GraphInfo"

    return $functionConnectionType
}

#*****************************************************
Function Connect-MicrosoftGraph 
{
    [cmdletbinding()]

    Param
    (
        [string]$msGraphEnvironmentName,
        [Parameter(Mandatory=$true)]
        [string]$msGraphTenantID,
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$msGraphApplicationID,
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$msGraphCertificateThumbprint,
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$msGraphClientSecret,
        [Parameter(Mandatory=$true)]
        [string]$graphAuthenticationType
    )

    out-logfile -string "Entering Connect-MicrosoftGraph"

    $functionConnectionTypeInteractive = "Interactive"
    $functionConnectionTypeCertificate = "CertAuth"
    $functionConnectionTypeSecret = "ClientSecret"

    if ($graphAuthenticationType -eq $functionConnectionTypeInteractive)
    {
        out-logfile -string "Interactive Authentication"

        try {
            connect-mgGraph -TenantId $msGraphTenantID -environment $msGraphEnvironmentName -errorAction Stop

            out-logfile -string "Interactive authentication to Microosft Graph successful."
        }
        catch {
            out-logfile -string "Interactive authentication to Microsoft Graph FAILED."
            out-logfile -string $_ -isError:$true
        }
    }
    elseif ($graphAuthenticationType -eq $functionConnectionTypeCertificate)
    {
        out-logfile -string "Certificate Authentication"

        try {
            connect-mgGraph -TenantId $msGraphTenantID -Environment $msGraphEnvironmentName -ClientId $msGraphApplicationID -CertificateThumbprint $msGraphCertificateThumbprint -errorAction Stop

            out-logfile -string "Certificate authentication to Microsoft Graph successful."
        }
        catch {
            out-logfile -string "Certificate authentication to Microsoft Graph FAILED."
            out-logfile -string $_ -isError:$TRUE
        }
    }
    elseif ($graphAuthenticationType -eq $functionConnectionTypeSecret)
    {
        out-logfile -string "Client Secret Authentication"

        $securedPasswordPassword = convertTo-SecureString -string $msGraphClientSecret -AsPlainText -Force

        $clientSecretCredential = new-object -typeName System.Management.Automation.PSCredential -argumentList $msGraphApplicationID,$securedPasswordPassword

        try {
            Connect-MgGraph -tenantID $msGraphTenantID -environment $msGraphEnvironmentName -ClientSecretCredential $clientSecretCredential -errorAction Stop

            out-logfile -string "Client secret authentication to Microsoft Graph successful."
        }
        catch {
            out-logfile -string "Client secret authentication to Microsoft Graph FAILED."
            out-logfile -string $_ -isError:$TRUE
        }
    }
    else 
    {
        out-logfile -string "This is bad - you should not have been able to end up here." -isError:$TRUE
    }

    out-logfile -string "Exiting Connect-MicrosoftGraph"
}

#*****************************************************
Function Validate-GraphScopes 
{
    out-logfile -string "Entering Validate-GraphScopes"

    #Define local variables.

    $graphScopesRequired = @("GroupMember.Read.All","Group.ReadWrite.All","Directory.Read.All","Directory.ReadWrite.All","Group.Read.All")
    $graphContext = $NULL
    $validGraphScope = ""

    out-logfile -string "Exiting Validate-GraphScopes"

    out-logfile -string "Obtaining graph context."

    $graphContext = Get-MgContext

    out-logfile -string "The following scopes are assigned to the authentication context:"

    foreach ($scope in $graphContext.scopes)
    {
        out-logfile -string $scope
    }

    out-logfile -string "Searching scopes to ensure a minimum scope is present."

    for ($i = 0 ; $i -lt $graphContext.Scopes.Count ; $i++)
    {
        out-logfile -string $graphContext.scopes[$i]

        if ($graphScopesRequired.Contains($graphContext.scopes[$i]))
        {
            out-logfile -string "Minium graph scope found - proceed."
            $validGraphScope = $graphContext.scopes[$i]
            $i = $graphContext.Scopes.Count+1
        }
        else 
        {
            out-logfile -string "Not a minimum graph scope."
        }
    }

    if ($validGraphScope -eq "")
    {
        out-logfile -string "A valid graph scope for continuing was not found in the authentication context."
        out-logfile -string "The user or application must have one of the following scopes:"

        foreach ($scope in $graphScopesRequired)
        {
            out-logfile -string $scope
        }

        out-logfile -string "ERROR: Correct graph scopes!"
    }
}

#*****************************************************
#*****************************************************

#Start main function

#*****************************************************
#*****************************************************

#Declare variables

[string]$logFileName = "GroupExpirationAudit"
[string]$graphConnectionType = ""
[string]$backSlash = "\"

new-LogFile -logFileName $logFileName -logFolderPath $logFolderPath

out-logfile -string "Starting GroupExpirationAudit"

out-logfile -string "Validating graph parameters provided"

$graphConnectionType = Validate-GraphInfo -msGraphApplicationID $msGraphApplicationID -msGraphCertificateThumbprint $msGraphCertificateThumbprint -msGraphClientSecret $msGraphClientSecret -errorAction STOP

out-logfile -string ("Graph authentication type: "+$graphConnectionType)

out-logfile -string "Initiating connection to Microsoft Graph."

Connect-MicrosoftGraph -msGraphEnvironmentName $msGraphEnvironmentName -msGraphTenantID $msGraphTenantID -msGraphApplicationID $msGraphApplicationID -msGraphCertificateThumbprint $msGraphCertificateThumbprint -msGraphClientSecret $msGraphClientSecret -graphAuthenticationType $graphConnectionType -errorAction STOP

out-logfile -string "Validating necessary graph scopes post connection."

Validate-GraphScopes