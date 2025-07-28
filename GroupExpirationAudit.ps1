
<#PSScriptInfo

.VERSION 1.1

.GUID 79d1df22-ec96-4860-b2d4-40dafb649ae1

.AUTHOR timmcmic

.COMPANYNAME Micorosft CSS

.COPYRIGHT

.TAGS

.LICENSEURI

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES

.DESCRIPTION "This script allows administators to report on Group Expiration."

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
        [string]$logFolderPath,
        [Parameter(Mandatory = $false)]
        [boolean]$includePolicyEvaluation=$TRUE
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

    out-logfile -string 'Exiting Validate-GraphScopes'
}

#*****************************************************
Function Get-M365Groups 
{
    out-logfile -string "Entering Get-M365Groups"

    #Declare variables.

    $groupReturn = $null
    $groupType = "Unified"

    out-logfile -string "Obtaining all M365 / Unified Groups by Filter"

    try {
        $groupReturn = Get-MgGroup -Filter "groupTypes/any(c:c eq '$groupType')" -All -PageSize 500 -ConsistencyLevel Eventual -Property DisplayName, ID, CreatedDateTime, RenewedDateTime, ExpirationDateTime
    }
    catch {
        out-logfile $_ -isError:$true
    }

    out-logfile -string 'Exiting Get-M365Group'

    return $groupReturn
}

#*****************************************************
Function Get-M365GroupsDeleted 
{
    out-logfile -string "Entering Get-M365GroupsDeleted"

    #Declare variables.

    $groupReturn = $null
    $groupType = "Unified"

    out-logfile -string "Obtaining all M365 Deleted Groups"

    try {
        $groupReturn = Get-MgDirectoryDeletedItemAsGroup -All -PageSize 500 -Property DisplayName, ID, CreatedDateTime, RenewedDateTime, ExpirationDateTime
    }
    catch {
        out-logfile $_ -isError:$true
    }

    out-logfile -string 'Exiting Get-M365GroupsDeleted'

    return $groupReturn
}

#*****************************************************
Function Calculate-GroupExpiration
{
    #Give credit where credit is due.
    #Code largely adapted from https://office365itpros.com/2022/02/09/microsoft-groups-expiration-policy/
    #Code modified to account for groups that may not have a renewal date or expiration date.

    Param
    (
        [Parameter(Mandatory=$true)]
        $groupsToEvaluate,
        [Parameter(Mandatory=$true)]
        $isDeleted
    )

    out-logfile -string "Entering Calculate-GroupExpiration"

    #Declare variables.

    $functionGroups = [System.Collections.Generic.List[Object]]::new()
    $today = (Get-Date)
    $functionNo = "No"
    $functionYes = "Yes"

    foreach ($group in $groupsToEvaluate)
    {
        out-logfile -string ("Evaluting group: "+$group.DisplayName)
        out-logfile -string ("Evaluating group id: "+$group.id)

        $Days = (New-TimeSpan -Start $group.CreatedDateTime -End $Today).Days  # Age of group
        $createdOn = Get-Date($group.CreatedDateTime) -format 'dd-MMM-yyyy HH:mm'

        out-logfile -string ("Age of group in days: "+$Days)
        out-logfile -string ("Group created on: "+$createdOn)

        if ($group.ExpirationDateTime -ne $null)
        {
            out-logfile -string "Group has expiration date - evaluate."

            $DaysLeft = (New-TimeSpan -Start $Today -End $group.ExpirationDateTime).Days
            $nextRenewal = Get-Date($group.ExpirationDateTime) -format 'dd-MMM-yyyy'
        }
        else 
        {
            $DaysLeft = "N/A"
            $nextRenewal = "N/A"
        }

        out-logfile -string ("Days till group expiration: "+$DaysLeft)
        out-logfile -string ("Expiration Date: "+$nextRenewal)

        if ($group.RenewedDateTime -ne $null)
        {
            out-logfile -string "Group has last renewed date - evaluate."

            $lastRenewal = Get-Date($group.RenewedDateTime) -format 'dd-MMM-yyyy'
        }
        else 
        {
            $lastRenewal = "N/A"
        }

        out-logfile -string ("Last Renewed Date: "+$lastRenewal)

        if ($isDeleted -eq $functionNo)
        {
            $ReportLine = [PSCustomObject]@{
            Group                   = $group.DisplayName
            GroupID                 = $group.id
            Created                 = $createdOn
            "Age in days"            = $Days
            "Last Renewed"           = $lastRenewal
            "Next Renewal"           = $nextRenewal
            "Days Before Expiration" = $DaysLeft
            "Group Expiration Policy ID" = ""
            IsDeleted = $functionNo}
        }
        elseif ($isDeleted -eq $functionYes)
        {
            $ReportLine = [PSCustomObject]@{
            Group                   = $group.DisplayName
            GroupID                 = $group.id
            Created                 = $createdOn
            "Age in days"            = $Days
            "Last Renewed"           = $lastRenewal
            "Next Renewal"           = $nextRenewal
            "Days Before Expiration" = $DaysLeft
            "Group Expiration Policy ID" = ""
            IsDeleted = $functionYes}
        }
        else 
        {
            out-logfile -string "You should not have ended up here." -isError:$true
        }
        

      $functionGroups.Add($ReportLine)
    }

    out-logfile -string 'Exiting Calculate-GroupExpiration'

    return $functionGroups
}

#*****************************************************
Function Calculate-ExpirationPolicy
{
    Param
    (
        [Parameter(Mandatory=$true)]
        $groupsToEvaluate,
        [Parameter(Mandatory=$true)]
        $groupsExpirationPolicy
    )

    $groupExpirationPolicySelected = "Selected"

    out-logfile -string "Entering Calculate-ExpirationPolicy"

    foreach ($group in $groupsToEvaluate)
    {
        out-logfile -string ("Evaluting group: "+$group.group)
        out-logfile -string ("Evaluating group id: "+$group.groupID)
        
        if ($groupsExpirationPolicy.ManagedGroupTypes -eq $groupExpirationPolicySelected)
        {
            out-logfile -string "Group expiration policy is scoped to selected groups - evaluate group."
            $id = $group.groupID
            $uri = "https://graph.microsoft.com/v1.0/groups/$id/groupLifecyclePolicies"

            out-logfile -string $uri

            try {
                $policy = Invoke-MgGraphRequest -Method "Get" -Uri $uri -ErrorAction Stop

                if ($policy.value.id -ne $NULL)
                {
                    out-logfile -string ("Group has expiration policy id: "+$policy.value.id)
                    $group.'Group Expiration Policy ID' = $policy.value.id
                }
                else 
                {
                    out-logfile -string ("Group does not have expiration policy id.")
                    $group.'Group Expiration Policy ID' = "None"
                }
            }
            catch {
                $group.'Group Expiration Policy ID' = "None"
            }
        }
        else 
        {
            out-logfile -string "Group expiration policy applies to all groups - update ID."
            $group.'Group Expiration Policy ID' = $groupExpirationPolicy.id
        }

        out-logfile -string $group
    }

    out-logfile -string 'Exiting Calculate-ExpirationPolicy'

    return $groupsToEvaluate
}

#*****************************************************
Function Get-GroupExpirationPolicy
{
    out-logfile -string "Entering Get-GroupExpirationPolicy"

    try {
        $functionPolicy = Get-MgGroupLifecyclePolicy -errorAction STOP

        out-logfile -string 'Successfully obtained lifecycle policy.'
        out-logfile -string $functionPolicy
    }
    catch {
        out-logfile -string 'Unable to obtain group lifecycle policy.'
        out-logfile -string $_ -isError:$true
    }

    out-logfile -string 'Exiting Get-GroupExpirationPolicy'

    return $functionPolicy
}

#*****************************************************
Function WriteXMLFile
{
    [cmdletbinding()]

    Param
    (
        [Parameter(Mandatory = $true)]
        $outputFile,
        [Parameter(Mandatory = $true)]
        $data
    )

    out-logfile -string "Entering WriteXMLFile"

    try
    {
        out-logfile -string "Writing outout to xml file."

        $data | export-cliXML -path $outputFile -errorAction STOP
    }
    catch
    {
        out-logfile -string $_
        out-logfile -string "Unable to write data to XML file." -isError:$TRUE
    }
    
        out-logfile -string "Exiting WriteXMLFile"
}

#*****************************************************
Function WriteCSVFile
{
    [cmdletbinding()]

    Param
    (
        [Parameter(Mandatory = $true)]
        $outputFile,
        [Parameter(Mandatory = $true)]
        $data
    )

    out-logfile -string "Entering WriteCSVFile"

    try
    {
        out-logfile -string "Writing outout to csv file."

        $data | Export-Csv -path $outputFile -errorAction STOP
    }
    catch
    {
        out-logfile -string $_
        out-logfile -string "Unable to write data to CSV file." -isError:$TRUE
    }

    out-logfile -string "Exiting WriteCSVFile"
}

#*****************************************************
Function Generate-HTMLFile
{
    [cmdletbinding()]

    Param
    (
        [Parameter(Mandatory = $true)]
        $groupsOutput,
        [Parameter(Mandatory = $true)]
        $expirationSettings,
        [Parameter(Mandatory = $true)]
        [boolean]$evaluatePolicy
    )

    out-logfile -string "Entering Generate-HTMLData"

    $no = "No"
    $yes = "Yes"
    $functionHTMLSuffix = "HTML"
    $functionLogSuffix = "log"
    $functionHTMLFile = $global:LogFile.replace("$functionLogSuffix","$functionHTMLSuffix")
    $headerString = "Group Expiration Audit"

    $totalActiveGroupsEvaluated = ($groupsOutput | where {$_.isDeleted -eq $No}).count
    $totalDeletedGroupsEvaluated = ($groupsOutput | where {$_.isDeleted -eq $Yes}).count
    $totalGroupsEvaluated = $groupsOutput.count

    if ($evaluatePolicy -eq $TRUE)
    {
        $groupPolicyCount = ($groupsOutput | where {($_.'Group Expiration Policy ID' -ne "") -and ($_.'Group Expiration Policy ID' -ne "None")}).count
        $activePolicyCount = ($groupsOutput | where {($_.'Group Expiration Policy ID' -ne "") -and ($_.'Group Expiration Policy ID' -ne "None") -and ($_.isDeleted -eq $no)}).count
        $deletedPolicyCount = ($groupsOutput | where {($_.'Group Expiration Policy ID' -ne "") -and ($_.'Group Expiration Policy ID' -ne "None") -and ($_.isDeleted -eq $yes)}).count
        $noGroupPolicyCount = ($groupsOutput | where {($_.'Group Expiration Policy ID' -eq "None")}).count
        $notEvaluatedCount = "N/A"
    }
    else
    {
        $groupPolicyCount = "N/A"
        $activePolicyCount = "N/A"
        $deletedPolicyCount = "N/A"
        $noGroupPolicyCount = "N/A"
        $notEvaluatedCount = ($groupsOutput | where {($_.'Group Expiration Policy ID' -eq "")}).count  
    }

    new-HTML -TitleText $headerString -FilePath $functionHTMLFile {
        New-HTMLHeader {
            New-HTMLText -Text $headerString -FontSize 24 -Color White -BackGroundColor Black -Alignment center
        }
        new-htmlMain{
            New-HTMLTableOption -DataStore JavaScript

            New-htmlSection -HeaderText ("Group Expiration Information"){
                new-htmlTable -DataTable ($groupsOutput | Select-Object Group,GroupID,Created,'Age In Days','Last Renewed','Next Renewal','Days Before Expiration','Group Expiration Policy ID','IsDeleted') -Filtering {
                } -AutoSize
            } -HeaderTextAlignment "Left" -HeaderTextSize "16" -HeaderTextColor "White" -HeaderBackGroundColor "Black"  -CanCollapse -BorderRadius 10px -collapsed

            New-htmlSection -HeaderText ("Group Expiration Policy Information"){
                new-htmlTable -DataTable ($expirationSettings | select-object ID,GroupLifeTimeInDays,AlternateNotificationEmails,ManagedGroupTypes) -Filtering {
                } -AutoSize
            } -HeaderTextAlignment "Left" -HeaderTextSize "16" -HeaderTextColor "White" -HeaderBackGroundColor "Black"  -CanCollapse -BorderRadius 10px -collapsed
            New-HTMLSection -HeaderText "Group Evaluation Summary" {
                new-htmlList{
                    new-htmlListItem -text ("Groups With Policy ID: "+$groupPolicyCount) -FontSize 14
                    new-htmlList{
                        new-htmlListItem -text ("Active Groups With Policy ID: "+$activePolicyCount) -FontSize 14
                        new-htmlListItem -text ("Deleted Groups With Policy ID: "+$deletedPolicyCount) -FontSize 14
                    }
                    new-htmlListItem -text ("Groups Without Policy ID: "+$noGroupPolicyCount) -FontSize 14
                    new-htmlListItem -text ("Groups Not Evaluated For PolicyID: "+$notEvaluatedCount) -FontSize 14

                    new-htmlListItem -text ("Total Groups Evaluated: "+$totalGroupsEvaluated) -FontSize 14
                    New-HTMLList{
                        new-htmlListItem -text ("Total Active Groups Evaluated: "+$totalActiveGroupsEvaluated) -FontSize 14
                        new-htmlListItem -text ("Total Deleted Groups Evaluated: "+$totalDeletedGroupsEvaluated) -FontSize 14
                    }
                }
            }-HeaderTextAlignment "Left" -HeaderTextSize "16" -HeaderTextColor "White" -HeaderBackGroundColor "Black"  -CanCollapse -BorderRadius 10px -collapsed
        }
    } -online -ShowHTML

    out-logfile -string "Exiting Generate-HTMLData"
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
$groupsToEvaluate = $null
$groupsToEvaluateDeleted = $null

$Yes = "Yes"
$No = "no"

$groupsOutput=[System.Collections.Generic.List[Object]]::new()
$groupExpirationPolicy = $null
[string]$logFileNameFull = $logFileName +".log"
[string]$m365GroupsXML = "Groups.xml"
[string]$m365GroupsInfo = "GroupsExpirationReport.csv"
[string]$m365GroupsPolicy = "GroupsPolicyInfo.xml"
[string]$m365GroupsDeleted = "GroupsDeleted.xml"

new-LogFile -logFileName $logFileName -logFolderPath $logFolderPath

$outputM365Groups = $global:LogFile.replace($logFileNameFull,$m365GroupsXML)
$outputM365GroupsInfo = $global:LogFile.replace($logFileNameFull,$m365GroupsInfo)
$outputM365GroupsPolicy = $global:LogFile.replace($logFileNameFull,$m365GroupsPolicy)
$outputM365GroupsDeleted = $global:LogFile.replace($logFileNameFull,$m365GroupsDeleted)

out-logfile -string "Starting GroupExpirationAudit"

out-logfile -string "Validating graph parameters provided"

$graphConnectionType = Validate-GraphInfo -msGraphApplicationID $msGraphApplicationID -msGraphCertificateThumbprint $msGraphCertificateThumbprint -msGraphClientSecret $msGraphClientSecret -errorAction STOP

out-logfile -string ("Graph authentication type: "+$graphConnectionType)

out-logfile -string "Initiating connection to Microsoft Graph."

Connect-MicrosoftGraph -msGraphEnvironmentName $msGraphEnvironmentName -msGraphTenantID $msGraphTenantID -msGraphApplicationID $msGraphApplicationID -msGraphCertificateThumbprint $msGraphCertificateThumbprint -msGraphClientSecret $msGraphClientSecret -graphAuthenticationType $graphConnectionType -errorAction STOP

out-logfile -string "Validating necessary graph scopes post connection."

Validate-GraphScopes

out-logfile -string "Obtain all M365 or Unified Group types for evaluation."

$groupsToEvaluate = Get-M365Groups

out-logfile -string "Obtain all M365 or Unified Group Deleted for evaluation."

$groupsToEvaluateDeleted = Get-M365GroupsDeleted

out-logfile -string "Obtain group expiration policy details."

$groupExpirationPolicy = Get-GroupExpirationPolicy

WriteXMLFile -outputFile $outputM365GroupsPolicy -data $groupExpirationPolicy

if (($groupsToEvaluate.count -gt 0) -or ($groupsToEvaluateDeleted.count -gt 0))
{
    out-logfile -string "Either active or deleted groups were located - evaluate."

    if ($groupsToEvaluate.count -gt 0)
    {
        out-logfile -string "M365 groups were located in Entra ID - proceed with evaluation."

        out-logfile -string "Calculate group expiration information and create objects."

        WriteXMLFile -outputFile $outputM365Groups -data $groupsToEvaluate

        $groupsOutput += Calculate-GroupExpiration -groupsToEvaluate $groupsToEvaluate -isDeleted $No
    }

    if ($groupsToEvaluateDeleted.count -gt 0)
    {
        out-logfile -string "M365 deleted groups were located in Entra ID - proceed with evaluation."

        out-logfile -string "Calculate group expiration information and create objects."

        WriteXMLFile -outputFile $outputM365GroupsDeleted -data $groupsToEvaluate

        $groupsOutput += Calculate-GroupExpiration -groupsToEvaluate $groupsToEvaluateDeleted -isDeleted $Yes
    }

    if ($includePolicyEvaluation -eq $TRUE)
    {
        out-logfile -string "Policy evaluation is included."

        $groupsOutput = Calculate-ExpirationPolicy -groupsToEvaluate $groupsOutput -groupsExpirationPolicy $groupExpirationPolicy
    }
    else 
    {
        out-logfile -string "Policy evaluation was not included."
    }
    
    WriteCSVFile -outputFile $outputM365GroupsInfo -data $groupsOutput

    Generate-HTMLFile -groupsoutput $groupsOutput -expirationSettings $groupExpirationPolicy -evaluatePolicy $includePolicyEvaluation
}
else 
{
    out-logfile -string "M365 groups were not located in Entra ID - no further work to do."
}