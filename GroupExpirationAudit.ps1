
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
        [string]$msGraphClientSecret,
        #Define other mandatory parameters
        [Parameter(Mandatory = $true)]
        [string]$logFolderPath
)


