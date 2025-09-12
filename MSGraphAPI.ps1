# This script contains functions for MSGraph API at https://graph.microsoft.com

# Returns the 50 latest signin entries or the given entry
# Jun 9th 2020
function Get-AzureSignInLog
{
    <#
    .SYNOPSIS
    Returns the 50 latest entries from Azure AD sign-in log or single entry by id

    .DESCRIPTION
    Returns the 50 latest entries from Azure AD sign-in log or single entry by id

    .Example
    Get-AADIntAccessTokenForMSGraph
    PS C:\>Get-AADIntAzureSignInLog

    createdDateTime              id                                   ipAddress      userPrincipalName             appDisplayName                   
    ---------------              --                                   ---------      -----------------             --------------                   
    2020-05-25T05:54:28.5131075Z b223590e-8ba1-4d54-be54-03071659f900 199.11.103.31  admin@company.onmicrosoft.com Azure Portal                     
    2020-05-29T07:56:50.2565658Z f6151a97-98cc-444e-a79f-a80b54490b00 139.93.35.110  user@company.com              Azure Portal                     
    2020-05-29T08:02:24.8788565Z ad2cfeff-52f2-442a-b8fc-1e951b480b00 11.146.246.254 user2@company.com             Microsoft Docs                   
    2020-05-29T08:56:48.7857468Z e0f8e629-863f-43f5-a956-a4046a100d00 1.239.249.24   admin@company.onmicrosoft.com Azure Active Directory PowerShell

    .Example
    Get-AADIntAccessTokenForMSGraph
    PS C:\>Get-AADIntAzureSignInLog

    createdDateTime              id                                   ipAddress      userPrincipalName             appDisplayName                   
    ---------------              --                                   ---------      -----------------             --------------                   
    2020-05-25T05:54:28.5131075Z b223590e-8ba1-4d54-be54-03071659f900 199.11.103.31  admin@company.onmicrosoft.com Azure Portal                     
    2020-05-29T07:56:50.2565658Z f6151a97-98cc-444e-a79f-a80b54490b00 139.93.35.110  user@company.com              Azure Portal                     
    2020-05-29T08:02:24.8788565Z ad2cfeff-52f2-442a-b8fc-1e951b480b00 11.146.246.254 user2@company.com             Microsoft Docs                   
    2020-05-29T08:56:48.7857468Z e0f8e629-863f-43f5-a956-a4046a100d00 1.239.249.24   admin@company.onmicrosoft.com Azure Active Directory PowerShell

    PS C:\>Get-AADIntAzureSignInLog -EntryId b223590e-8ba1-4d54-be54-03071659f900

    id                 : b223590e-8ba1-4d54-be54-03071659f900
    createdDateTime    : 2020-05-25T05:54:28.5131075Z
    userDisplayName    : admin company
    userPrincipalName  : admin@company.onmicrosoft.com
    userId             : 289fcdf8-af4e-40eb-a363-0430bc98d4d1
    appId              : c44b4083-3bb0-49c1-b47d-974e53cbdf3c
    appDisplayName     : Azure Portal
    ipAddress          : 199.11.103.31
    clientAppUsed      : Browser
    userAgent          : Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36
    ...
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$EntryId,
        [switch]$Export
        
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        # Select one entry if provided
        if($EntryId)
        {
            $queryString = "`$filter=id eq '$EntryId'"
        }
        else
        {
            $queryString = "`$top=50&`$orderby=createdDateTime"
        }

        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "auditLogs/signIns" -QueryString $queryString

        # Return full results
        if($Export)
        {
            return $results
        }
        elseif($EntryId) # The single entry
        {
            return $results
        }
        else # Print out only some info - the API always returns all info as $Select is not supported :(
        {
            $results | select createdDateTime,id,ipAddress,userPrincipalName,appDisplayName | ft
        }
    }
}

# Returns the 50 latest signin entries or the given entry
# Jun 9th 2020
function Get-AzureAuditLog
{
    <#
    .SYNOPSIS
    Returns the 50 latest entries from Azure AD sign-in log or single entry by id

    .DESCRIPTION
    Returns the 50 latest entries from Azure AD sign-in log or single entry by id

    .Example
    Get-AADIntAccessTokenForMSGraph
    PS C:\>Get-AADIntAzureAuditLog

    id                                                            activityDateTime             activityDisplayName   operationType result  initiatedBy   
    --                                                            ----------------             -------------------   ------------- ------  -----------   
    Directory_9af6aff3-dc09-4ac1-a1d3-143e80977b3e_EZPWC_41985545 2020-05-29T07:57:51.4037921Z Add service principal Add           success @{user=; app=}
    Directory_f830a9d4-e746-48dc-944c-eb093364c011_1ZJAE_22273050 2020-05-29T07:57:51.6245497Z Add service principal Add           failure @{user=; app=}
    Directory_a813bc02-5d7a-4a40-9d37-7d4081d42b42_RKRRS_12877155 2020-06-02T12:49:38.5177891Z Add user              Add           success @{app=; user=}

    .Example
    Get-AADIntAccessTokenForMSGraph
    PS C:\>Get-AADIntAzureAuditLog

    id                                                            activityDateTime             activityDisplayName   operationType result  initiatedBy   
    --                                                            ----------------             -------------------   ------------- ------  -----------   
    Directory_9af6aff3-dc09-4ac1-a1d3-143e80977b3e_EZPWC_41985545 2020-05-29T07:57:51.4037921Z Add service principal Add           success @{user=; app=}
    Directory_f830a9d4-e746-48dc-944c-eb093364c011_1ZJAE_22273050 2020-05-29T07:57:51.6245497Z Add service principal Add           failure @{user=; app=}
    Directory_a813bc02-5d7a-4a40-9d37-7d4081d42b42_RKRRS_12877155 2020-06-02T12:49:38.5177891Z Add user              Add           success @{app=; user=}

    PS C:\>Get-AADIntAzureAuditLog -EntryId Directory_9af6aff3-dc09-4ac1-a1d3-143e80977b3e_EZPWC_41985545

    id                  : Directory_9af6aff3-dc09-4ac1-a1d3-143e80977b3e_EZPWC_41985545
    category            : ApplicationManagement
    correlationId       : 9af6aff3-dc09-4ac1-a1d3-143e80977b3e
    result              : success
    resultReason        : 
    activityDisplayName : Add service principal
    activityDateTime    : 2020-05-29T07:57:51.4037921Z
    loggedByService     : Core Directory
    operationType       : Add
    initiatedBy         : @{user=; app=}
    targetResources     : {@{id=66ce0b00-92ee-4851-8495-7c144b77601f; displayName=Azure Credential Configuration Endpoint Service; type=ServicePrincipal; userPrincipalName=; 
                          groupType=; modifiedProperties=System.Object[]}}
    additionalDetails   : {}
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$EntryId,
        [switch]$Export
        
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        # Select one entry if provided
        if($EntryId)
        {
            $queryString = "`$filter=id eq '$EntryId'"
        }
        else
        {
            $queryString = "`$top=50&`$orderby=activityDateTime"
        }

        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "auditLogs/directoryAudits" -QueryString $queryString

        # Return full results
        if($Export)
        {
            return $results
        }
        elseif($EntryId) # The single entry
        {
            return $results
        }
        else # Print out only some info - the API always returns all info as $Select is not supported :(
        {
            $results | select id,activityDateTime,activityDisplayName,operationType,result,initiatedBy | ft
        }
    }
}

function Get-AADUsers
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$SearchString,
        [Parameter(Mandatory=$False)]
        [String]$UserPrincipalName
        
    )
    Process
    {
        if(![string]::IsNullOrEmpty($SearchString))
        {
            $queryString="`$filter=(startswith(displayName,'$SearchString') or startswith(userPrincipalName,'$SearchString'))"
        }
        elseif(![string]::IsNullOrEmpty($UserPrincipalName))
        {
            $queryString="`$filter=userPrincipalName eq '$UserPrincipalName'"
        }

        $results=Call-MSGraphAPI -AccessToken $AccessToken -API users -QueryString $queryString

        return $results
    }
}

# Gets the user's data
# Jun 16th 2020
function Get-MSGraphUser
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$UserPrincipalName
    )
    Process
    {
        # Url encode for external users, replace # with %23
        $UserPrincipalName = $UserPrincipalName.Replace("#","%23")

        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserPrincipalName" -ApiVersion "v1.0" -QueryString "`$select=businessPhones,displayName,givenName,id,jobTitle,mail,mobilePhone,officeLocation,preferredLanguage,surname,userPrincipalName,onPremisesDistinguishedName,onPremisesExtensionAttributes,onPremisesImmutableId,onPremisesLastSyncDateTime,onPremisesSamAccountName,onPremisesSecurityIdentifier,refreshTokensValidFromDateTime,signInSessionsValidFromDateTime,usageLocation,provisionedPlans,proxyAddresses"

        return $results
    }
}

# Gets the user's application role assignments
# Jun 16th 2020
function Get-MSGraphUserAppRoleAssignments
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$UserPrincipalName
    )
    Process
    {
        # Url encode for external users, replace # with %23
        $UserPrincipalName = $UserPrincipalName.Replace("#","%23")

        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserPrincipalName/appRoleAssignments" -ApiVersion v1.0

        return $results
    }
}

# Gets the user's owned devices
# Jun 16th 2020
function Get-MSGraphUserOwnedDevices
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$UserPrincipalName
    )
    Process
    {
        # Url encode for external users, replace # with %23
        $UserPrincipalName = $UserPrincipalName.Replace("#","%23")

        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserPrincipalName/ownedDevices" -ApiVersion v1.0

        return $results
    }
}

# Gets the user's registered devices
# Jun 16th 2020
function Get-MSGraphUserRegisteredDevices
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$UserPrincipalName
    )
    Process
    {
        # Url encode for external users, replace # with %23
        $UserPrincipalName = $UserPrincipalName.Replace("#","%23")

        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserPrincipalName/registeredDevices" -ApiVersion v1.0

        return $results
    }
}

# Gets the user's licenses
# Jun 16th 2020
function Get-MSGraphUserLicenseDetails
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$UserPrincipalName
    )
    Process
    {
        # Url encode for external users, replace # with %23
        $UserPrincipalName = $UserPrincipalName.Replace("#","%23")

        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserPrincipalName/licenseDetails" -ApiVersion v1.0 

        return $results
    }
}

# Gets the user's groups
# Jun 16th 2020
function Get-MSGraphUserMemberOf
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$UserPrincipalName
    )
    Process
    {
        # Url encode for external users, replace # with %23
        $UserPrincipalName = $UserPrincipalName.Replace("#","%23")

        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserPrincipalName/memberOf" -ApiVersion v1.0

        return $results
    }
}

# Gets the user's direct reports
# Jun 16th 2020
function Get-MSGraphUserDirectReports
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$UserPrincipalName
    )
    Process
    {
        # Url encode for external users, replace # with %23
        $UserPrincipalName = $UserPrincipalName.Replace("#","%23")

        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserPrincipalName/directReports" -ApiVersion v1.0 -QueryString "`$select=businessPhones,displayName,givenName,id,jobTitle,mail,mobilePhone,officeLocation,preferredLanguage,surname,userPrincipalName,onPremisesDistinguishedName,onPremisesExtensionAttributes,onPremisesImmutableId,onPremisesLastSyncDateTime,onPremisesSamAccountName,onPremisesSecurityIdentifier,refreshTokensValidFromDateTime,signInSessionsValidFromDateTime,usageLocation,provisionedPlans,proxyAddresses"

        return $results
    }
}

# Gets the user's manager
# Jun 16th 2020
function Get-MSGraphUserManager
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$UserPrincipalName
    )
    Process
    {
        # Url encode for external users, replace # with %23
        $UserPrincipalName = $UserPrincipalName.Replace("#","%23")

        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserPrincipalName/manager" -ApiVersion v1.0 -QueryString "`$select=businessPhones,displayName,givenName,id,jobTitle,mail,mobilePhone,officeLocation,preferredLanguage,surname,userPrincipalName,onPremisesDistinguishedName,onPremisesExtensionAttributes,onPremisesImmutableId,onPremisesLastSyncDateTime,onPremisesSamAccountName,onPremisesSecurityIdentifier,refreshTokensValidFromDateTime,signInSessionsValidFromDateTime,usageLocation,provisionedPlans,proxyAddresses"

        return $results
    }
}

# Gets the group's owners
# Jun 16th 2020
function Get-MSGraphGroupOwners
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$GroupId
    )
    Process
    {
        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "groups/$GroupId/owners" -ApiVersion v1.0 -QueryString "`$select=businessPhones,displayName,givenName,id,jobTitle,mail,mobilePhone,officeLocation,preferredLanguage,surname,userPrincipalName,onPremisesDistinguishedName,onPremisesExtensionAttributes,onPremisesImmutableId,onPremisesLastSyncDateTime,onPremisesSamAccountName,onPremisesSecurityIdentifier,refreshTokensValidFromDateTime,signInSessionsValidFromDateTime,usageLocation,provisionedPlans,proxyAddresses"

        return $results
    }
}

# Gets the group's members
# Jun 16th 2020
function Get-MSGraphGroupMembers
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$GroupId
    )
    Process
    {
        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "groups/$GroupId/members" -ApiVersion v1.0 -QueryString "`$top=500&`$select=businessPhones,displayName,givenName,id,jobTitle,mail,mobilePhone,officeLocation,preferredLanguage,surname,userPrincipalName,onPremisesDistinguishedName,onPremisesExtensionAttributes,onPremisesImmutableId,onPremisesLastSyncDateTime,onPremisesSamAccountName,onPremisesSecurityIdentifier,refreshTokensValidFromDateTime,signInSessionsValidFromDateTime,usageLocation,provisionedPlans,proxyAddresses"

        return $results
    }
}

# Gets the role's members
# Jun 17th 2020
function Get-MSGraphRoleMembers
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$RoleId
    )
    Process
    {
        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "directoryRoles/$RoleId/members" -ApiVersion v1.0 -QueryString "`$select=businessPhones,displayName,givenName,id,jobTitle,mail,mobilePhone,officeLocation,preferredLanguage,surname,userPrincipalName,onPremisesDistinguishedName,onPremisesExtensionAttributes,onPremisesImmutableId,onPremisesLastSyncDateTime,onPremisesSamAccountName,onPremisesSecurityIdentifier,refreshTokensValidFromDateTime,signInSessionsValidFromDateTime,usageLocation,provisionedPlans,proxyAddresses"

        return $results
    }
}

# Gets the tenant domains (all of them)
# Jun 16th 2020
function Get-MSGraphDomains
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken
    )
    Process
    {
        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "domains" -ApiVersion "v1.0"

        return $results
    }
}

# Gets team information
# Jun 17th 2020
function Get-MSGraphTeams
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$GroupId
    )
    Process
    {
        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "teams/$GroupId" -ApiVersion "v1.0"

        return $results
    }
}

# Gets team's app information
# Jun 17th 2020
function Get-MSGraphTeamsApps
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$GroupId
    )
    Process
    {
        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "teams/$GroupId/installedApps?`$expand=teamsAppDefinition" -ApiVersion v1.0

        return $results
    }
}

# Gets the authorizationPolicy
# Sep 18th 2020
function Get-TenantAuthPolicy
{
<#
    .SYNOPSIS
    Gets tenant's authorization policy.

    .DESCRIPTION
    Gets tenant's authorization policy, including user and guest settings.

    .PARAMETER AccessToken
    Access token used to retrieve the authorization policy.

    .Example
    Get-AADIntAccessTokenForMSGraph
    PS C:\>Get-AADIntTenantAuthPolicy

    id                                                : authorizationPolicy
    allowInvitesFrom                                  : everyone
    allowedToSignUpEmailBasedSubscriptions            : True
    allowedToUseSSPR                                  : True
    allowEmailVerifiedUsersToJoinOrganization         : False
    blockMsolPowerShell                               : False
    displayName                                       : Authorization Policy
    description                                       : Used to manage authorization related settings across the company.
    enabledPreviewFeatures                            : {}
    guestUserRoleId                                   : 10dae51f-b6af-4016-8d66-8c2a99b929b3
    permissionGrantPolicyIdsAssignedToDefaultUserRole : {microsoft-user-default-legacy}
    defaultUserRolePermissions                        : @{allowedToCreateApps=True; allowedToCreateSecurityGroups=True; allowedToReadOtherUsers=True}

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        $results = Call-MSGraphAPI -AccessToken $AccessToken -API "policies/authorizationPolicy" -ApiVersion "v1.0"

        return $results
    }
}

# Gets the guest account restrictions
# Sep 18th 2020
function Get-TenantGuestAccess
{
<#
    .SYNOPSIS
    Gets the guest access level of the user's tenant.

    .DESCRIPTION
    Gets the guest access level of the user's tenant.

    Inclusive:  Guest users have the same access as members
    Normal:     Guest users have limited access to properties and memberships of directory objects
    Restricted: Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)

    .PARAMETER AccessToken
    Access token used to retrieve the access level.

    .Example
    Get-AADIntAccessTokenForMSGraph -SaveToCache
    PS C:\>Get-AADIntTenantGuestAccess

    Access Description                                                                        RoleId                              
    ------ -----------                                                                        ------                              
    Normal Guest users have limited access to properties and memberships of directory objects 10dae51f-b6af-4016-8d66-8c2a99b929b3
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        $policy = Get-TenantAuthPolicy -AccessToken $AccessToken

        $roleId = $policy.guestUserRoleId

        
        switch($roleId)
        {
            "a0b1b346-4d3e-4e8b-98f8-753987be4970" {
                $attributes=[ordered]@{
                    "Access" =      "Full"
                    "Description" = "Guest users have the same access as members"
                }
                break
            }
            "10dae51f-b6af-4016-8d66-8c2a99b929b3" {
                $attributes=[ordered]@{
                    "Access" =      "Normal"
                    "Description" = "Guest users have limited access to properties and memberships of directory objects"
                }
                break
            }
            "2af84b1e-32c8-42b7-82bc-daa82404023b" {
                $attributes=[ordered]@{
                    "Access" =      "Restricted"
                    "Description" = "Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)"
                }
                break
            }
        }

        $attributes["RoleId"] = $roleId

        return New-Object psobject -Property $attributes


    }
}

# Sets the guest account restrictions
# Sep 18th 2020
function Set-TenantGuestAccess
{
<#
    .SYNOPSIS
    Sets the guest access level for the user's tenant.

    .DESCRIPTION
    Sets the guest access level for the user's tenant.

    Inclusive:  Guest users have the same access as members
    Normal:     Guest users have limited access to properties and memberships of directory objects
    Restricted: Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)

    .PARAMETER AccessToken
    Access token used to retrieve the access level.

    .PARAMETER Level
    Guest access level. One of Inclusive, Normal, or Restricted.

    .Example
    Get-AADIntAccessTokenForMSGraph
    PS C:\>Set-AADIntTenantGuestAccess -Level Normal

    Access Description                                                                        RoleId                              
    ------ -----------                                                                        ------                              
    Normal Guest users have limited access to properties and memberships of directory objects 10dae51f-b6af-4016-8d66-8c2a99b929b3
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        
        [Parameter(Mandatory=$True)]
        [ValidateSet('Full','Normal','Restricted')]
        [String]$Level
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"
        
        switch($Level)
        {
            "Full"       {$roleId = "a0b1b346-4d3e-4e8b-98f8-753987be4970"; break}
            "Normal"     {$roleId = "10dae51f-b6af-4016-8d66-8c2a99b929b3"; break}
            "Restricted" {$roleId = "2af84b1e-32c8-42b7-82bc-daa82404023b"; break}
        }
        $body = "{""guestUserRoleId"":""$roleId""}"


        Call-MSGraphAPI -AccessToken $AccessToken -API "policies/authorizationPolicy/authorizationPolicy" -Method "PATCH" -Body $body

        Get-TenantGuestAccess -AccessToken $AccessToken

    }
}


# Enables Msol PowerShell access
# Sep 18th 2020
function Enable-TenantMsolAccess
{
<#
    .SYNOPSIS
    Enables Msol PowerShell module access for the user's tenant.

    .DESCRIPTION
    Enables Msol PowerShell module access for the user's tenant.

    .PARAMETER AccessToken
    Access token used to enable the Msol PowerShell access.

    .Example
    Get-AADIntAccessTokenForMSGraph
    PS C:\>Enable-AADIntTenantMsolAccess

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        $body = '{"blockMsolPowerShell":"false"}'

        Call-MSGraphAPI -AccessToken $AccessToken -API "policies/authorizationPolicy/authorizationPolicy" -Method "PATCH" -Body $body
    }
}

# Disables Msol PowerShell access
# Sep 18th 2020
function Disable-TenantMsolAccess
{
<#
    .SYNOPSIS
    Disables Msol PowerShell module access for the user's tenant.

    .DESCRIPTION
    Disables Msol PowerShell module access for the user's tenant.

    .PARAMETER AccessToken
    Access token used to disable the Msol PowerShell access.

    .Example
    Get-AADIntAccessTokenForMSGraph
    PS C:\>Disable-AADIntTenantMsolAccess

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        $body = '{"blockMsolPowerShell":"true"}'

        Call-MSGraphAPI -AccessToken $AccessToken -API "policies/authorizationPolicy/authorizationPolicy" -Method "PATCH" -Body $body
    }
}

# Get rollout policies 
# Jan 7th 2021
function Get-RolloutPolicies
{
<#
    .SYNOPSIS
    Gets the tenant's rollout policies.

    .DESCRIPTION
    Gets the tenant's rollout policies.

    .PARAMETER AccessToken
    Access token used to get tenant's rollout policies.

    .Example
    Get-AADIntAccessTokenForMSGraph -SaveToCache
    PS C:\>Get-AADIntRolloutPolicies

    id                      : cdcb37e1-9c4a-4de9-a7f5-65fdf9f6241d
    displayName             : passthroughAuthentication rollout policy
    description             : 
    feature                 : passthroughAuthentication
    isEnabled               : True
    isAppliedToOrganization : False

    id                      : 3c89cd34-275c-4cba-8d8e-80338db7df91
    displayName             : seamlessSso rollout policy
    description             : 
    feature                 : seamlessSso
    isEnabled               : True
    isAppliedToOrganization : False
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "directory/featureRolloutPolicies" -ApiVersion beta
    }
}

# Get rollout policy groups 
# Jan 7th 2021
function Get-RolloutPolicyGroups
{
<#
    .SYNOPSIS
    Gets groups of the given rollout policy.

    .DESCRIPTION
    Gets groups of the given rollout policy.

    .PARAMETER AccessToken
    Access token used to get rollout policy groups.

    .PARAMETER PolicyId
    Guid of the rollout policy.

    .Example
    Get-AADIntAccessTokenForMSGraph -SaveToCache
    PS C:\>Get-AADIntRolloutPolicyGroups -PolicyId cdcb37e1-9c4a-4de9-a7f5-65fdf9f6241d | Select displayName,id

    displayName       id                                  
    -----------       --                                  
    PTA SSO Sales     b9faf3ba-db5f-4ed2-b9c8-0fd5916de1f3
    PTA SSO Markering f35d712f-dcdb-4040-a93d-ffd04aff3f75
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [GUID]$PolicyId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        $response=Call-MSGraphAPI -AccessToken $AccessToken -API "directory/featureRolloutPolicies/$($PolicyId.ToString())" -QueryString "`$expand=appliesTo" -ApiVersion beta
        $response.appliesTo
    }
}

# Add groups to rollout policy
# Jan 7th 2021
function Add-RolloutPolicyGroups
{
<#
    .SYNOPSIS
    Adds given groups to the given rollout policy.

    .DESCRIPTION
    Adds given groups to the given rollout policy. 
    
    Status meaning:
    204 The group successfully added
    400 Invalid group id
    404 Invalid policy id

    .PARAMETER AccessToken
    Access token used to add rollout policy groups.

    .PARAMETER PolicyId
    Guid of the rollout policy.

    .PARAMETER GroupIds
    List of group guids.

    .Example
    Get-AADIntAccessTokenForMSGraph -SaveToCache
    PS C:\>Add-AADIntRolloutPolicyGroups -PolicyId cdcb37e1-9c4a-4de9-a7f5-65fdf9f6241d -GroupIds b9faf3ba-db5f-4ed2-b9c8-0fd5916de1f3,f35d712f-dcdb-4040-a93d-ffd04aff3f75

    id                                   status
    --                                   ------
    b9faf3ba-db5f-4ed2-b9c8-0fd5916de1f3    204
    f35d712f-dcdb-4040-a93d-ffd04aff3f75    204
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [GUID]$PolicyId,
        [Parameter(Mandatory=$True)]
        [GUID[]]$GroupIds
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        # Build the body
        $requests = @()
        
        foreach($GroupId in $GroupIds)
        {
            $id = $GroupId.toString()
            $request = @{
                "id" =      $id
                "method" =  "POST"
                "url" =     "directory/featureRolloutPolicies/$($PolicyId.toString())/appliesTo/`$ref"
                "body" =    @{ "@odata.id" =    "https://graph.microsoft.com/beta/directoryObjects/$id" }
                "headers" = @{ "Content-Type" = "application/json" }
            }
            $requests += $request
        }

        $body = @{ "requests" = $requests } | ConvertTo-Json -Depth 5

        $response = Call-MSGraphAPI -AccessToken $AccessToken -API "`$batch" -ApiVersion beta -Method "POST" -Body $body

        if($response.responses[0].body.error.message)
        {
            Write-Error $response.responses[0].body.error.message
        }
        else
        {
            $response.responses | select id,status
        }
        
    }
}

# Removes groups from the rollout policy
# Jan 7th 2021
function Remove-RolloutPolicyGroups
{
<#
    .SYNOPSIS
    Removes given groups from the given rollout policy.

    .DESCRIPTION
    Removes given groups from the given rollout policy.
    
    Status meaning:
    204 The group successfully added
    400 Invalid group id
    404 Invalid policy id

    .PARAMETER AccessToken
    Access token used to remove rollout policy groups.

    .PARAMETER PolicyId
    Guid of the rollout policy.

    .PARAMETER GroupIds
    List of group guids.

    .Example
    Get-AADIntAccessTokenForMSGraph -SaveToCache
    PS C:\>Remove-AADIntRolloutPolicyGroups -PolicyId cdcb37e1-9c4a-4de9-a7f5-65fdf9f6241d -GroupIds b9faf3ba-db5f-4ed2-b9c8-0fd5916de1f3,f35d712f-dcdb-4040-a93d-ffd04aff3f75

    id                                   status
    --                                   ------
    b9faf3ba-db5f-4ed2-b9c8-0fd5916de1f3    204
    f35d712f-dcdb-4040-a93d-ffd04aff3f75    204
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [GUID]$PolicyId,
        [Parameter(Mandatory=$True)]
        [GUID[]]$GroupIds
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        # Build the body
        $requests = @()
        
        foreach($GroupId in $GroupIds)
        {
            $id = $GroupId.toString()
            $request = @{
                "id" =      $id
                "method" =  "DELETE"
                "url" =     "directory/featureRolloutPolicies/$($PolicyId.toString())/appliesTo/$id/`$ref"
            }
            $requests += $request
        }

        $body = @{ "requests" = $requests } | ConvertTo-Json -Depth 5

        $response = Call-MSGraphAPI -AccessToken $AccessToken -API "`$batch" -ApiVersion beta -Method "POST" -Body $body

        if($response.responses[0].body.error.message)
        {
            Write-Error $response.responses[0].body.error.message
        }
        else
        {
            $response.responses | select id,status
        }
        
    }
}

# Set rollout policy
# Jan 7th 2021
function Remove-RolloutPolicy
{
<#
    .SYNOPSIS
    Removes the given rollout policy.

    .DESCRIPTION
    Removes the given rollout policy. The policy MUST be disabled before it can be removed.

    .PARAMETER AccessToken
    Access token used to get tenant's rollout policies.

    .PARAMETER PolicyId
    Guid of the rollout policy.

    .Example
    Get-AADIntAccessTokenForMSGraph -SaveToCache
    PS C:\>Remove-AADIntRolloutPolicy -PolicyId 3c89cd34-275c-4cba-8d8e-80338db7df91

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [GUID]$PolicyId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "directory/featureRolloutPolicies/$($PolicyId.ToString())" -ApiVersion beta -Method DELETE
    }
}

# Set rollout policy
# Jan 7th 2021
function Set-RolloutPolicy
{
<#
    .SYNOPSIS
    Creates a new rollout policy or edits existing one.

    .DESCRIPTION
    Creates a new rollout policy by name or edits existing one with policy id. 

    .PARAMETER AccessToken
    Access token used to get tenant's rollout policies.

    .PARAMETER PolicyId
    Guid of the rollout policy.

    .PARAMETER Policy
    Name of the rollout policy. Can be one of: passwordHashSync, passthroughAuthentication, or seamlessSso

    .PARAMETER Enable
    Boolean value indicating is the feature enabled or not.

    .PARAMETER EnableToOrganization
    Boolean value indicating is the feature enabled for the whole organization. Currently not supported.

    .Example
    Get-AADIntAccessTokenForMSGraph -SaveToCache
    PS C:\>Set-AADIntRolloutPolicy -Policy passthroughAuthentication -Enable $True

    @odata.context          : https://graph.microsoft.com/beta/$metadata#directory/featureRolloutPolicies/$entity
    id                      : 1eec3ce2-5af1-4460-9cc4-1af7a6c15eb1
    displayName             : passthroughAuthentication rollout policy
    description             : 
    feature                 : passthroughAuthentication
    isEnabled               : True
    isAppliedToOrganization : False

    .Example
    Get-AADIntAccessTokenForMSGraph -SaveToCache
    PS C:\>Set-AADIntRolloutPolicy -PolicyId 1eec3ce2-5af1-4460-9cc4-1af7a6c15eb1 -Enable $False

    @odata.context          : https://graph.microsoft.com/beta/$metadata#directory/featureRolloutPolicies/$entity
    id                      : 1eec3ce2-5af1-4460-9cc4-1af7a6c15eb1
    displayName             : passthroughAuthentication rollout policy
    description             : 
    feature                 : passthroughAuthentication
    isEnabled               : True
    isAppliedToOrganization : False

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(ParameterSetName='id',Mandatory=$True)]
        [GUID]$PolicyId,
        [Parameter(Mandatory=$True)]
        [bool]$Enable,
        [Parameter(ParameterSetName='type',Mandatory=$True)]
        [ValidateSet('passwordHashSync','passthroughAuthentication','seamlessSso')]
        [String]$Policy,
        [Parameter(Mandatory=$False)]
        [bool]$EnableToOrganization = $false
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        try
        {
            if($Policy)
            {
                $body = @{
                    "feature" = "$Policy"
                    "isEnabled" = $Enable 
                    #"isAppliedToOrganization" = $EnableToOrganization
                    "displayName" = "$Policy rollout policy"}

                $response = Call-MSGraphAPI -AccessToken $AccessToken -API "directory/featureRolloutPolicies" -ApiVersion beta -Method POST -Body $($body | ConvertTo-Json -Depth 5)
            }
            else
            {
                $body = @{
                    "isEnabled" = $Enable
                    #"isAppliedToOrganization" = $EnableToOrganization 
                }

                $response = Call-MSGraphAPI -AccessToken $AccessToken -API "directory/featureRolloutPolicies/$($PolicyId.ToString())" -ApiVersion beta -Method PATCH -Body $($body | ConvertTo-Json -Depth 5)
            }
        }
        catch
        {
            $error = $_.ErrorDetails.Message | ConvertFrom-Json 
            Write-Error $error.error.message
        }

         
        $response
    }
}


# Return the default domain for the given tenantid
# Sep 28th 2022
function Get-TenantDomain
{
    <#
    .SYNOPSIS
    Returns the default domain for the given tenant id

    .DESCRIPTION
    Returns the default domain for the given tenant id

    .Example
    Get-AADIntAccessTokenForMSGraph -SaveToCache
    PS C:\>Get-AADIntTenantDomain -TenantId 72f988bf-86f1-41af-91ab-2d7cd011db47
    microsoft.onmicrosoft.com
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$TenantId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "tenantRelationships/findTenantInformationByTenantId(tenantId='$TenantId')" 
        
        Write-Verbose $results

        return $results.defaultDomainName
    }
}

# Adds a new TAP for the given user
# Jun 26th 2023
function New-UserTAP
{
    <#
    .SYNOPSIS
    Creates a new Temporary Access Pass (TAP) for the given user.

    .DESCRIPTION
    Creates a new Temporary Access Pass (TAP) for the given user.

    .PARAMETER

    .Example
    Get-AADIntAccessTokenForMSGraph -SaveToCache
    PS C:\>Get-AADIntTenantDomain -TenantId 72f988bf-86f1-41af-91ab-2d7cd011db47
    microsoft.onmicrosoft.com
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [switch]$UsableOnce,
        [Parameter(Mandatory=$False)]
        [ValidateRange(10, 43200)]
        [int]$Lifetime = 60,
        [Parameter(Mandatory=$False)]
        [DateTime]$StartTime = (Get-Date),
        [Parameter(Mandatory=$True)]
        [String]$User
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        # Create the body
        $body = @{
            "startDateTime"     = ($StartTime).ToUniversalTime().toString("yyyy-MM-ddTHH:mm:ssZ").Replace(".",":")
            "lifetimeInMinutes" = $Lifetime
            "isUsableOnce"      = $UsableOnce -eq $true
        }

        $results = Call-MSGraphAPI -AccessToken $AccessToken -API "users/$user/authentication/temporaryAccessPassMethods" -Method POST -Body ($body | ConvertTo-Json)
        
        return $results.temporaryAccessPass
    }
}

# Return B2C trust framework keysets
# Sep 13th 2022
function Get-B2CEncryptionKeys
{
<#
    .SYNOPSIS
    Gets B2C trust framework encryption keys. Can be used to create authorization codes and refresh tokens.

    .DESCRIPTION
    Gets B2C trust framework encryption keys. Can be used to create authorization codes and refresh tokens.
    Requires one of the following roles: B2C IEF Keyset Administrator, Global Reader, Global Administrator.

    .PARAMETER AccessToken
    AccessToken

    .Example
    Get-AADIntAccessTokenForMSGraph -SaveToCache
    PS C:\>Get-AADIntB2CEncryptionKeys
    
    Container                          Id                                          Key
    ---------                          --                                          ---
    B2C_1A_test                        XZ0q5X-Zu_oY2mX-El89a1YEsh4FRj0e5xpGMjJ94uE System.Security.Cryptography.RSACryptoServiceProvider
    B2C_1A_TokenEncryptionKeyContainer My_custom_key_id                            System.Security.Cryptography.RSACryptoServiceProvider
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        # Get all keysets
        $results=Call-MSGraphAPI -AccessToken $AccessToken -API "trustFramework/keySets" 
        
        # Loop through the results
        foreach($container in $results)
        {
            # Loop through the keys (can be more than one per container)
            foreach($key in $container.keys)
            {
                # Include only RSA encryption keys
                if($key.kty -eq "RSA" -and $key.use -eq "enc")
                {
                    # Create the parameters and RSA key
                    $RSAParameters = [System.Security.Cryptography.RSAParameters]::new()
                    $RSAParameters.Modulus = Convert-B64ToByteArray -B64 $key.n
                    $RSAParameters.Exponent = Convert-B64ToByteArray -B64 $key.e
                    $RSAKey = [System.Security.Cryptography.RSA]::Create()
                    $RSAKey.ImportParameters($RSAParameters)

                    # Return
                    [pscustomobject][ordered]@{
                        "Container" = $container.id
                        "Id" = $key.kid
                        "Key" = $RSAKey
                    }
                }
            }
        }
    }
}


function Get-MSGraphCAPolicies
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$TenantId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "d3590ed6-52b3-4102-aeff-aad2292ab01c" -Resource "https://graph.microsoft.com"

        # Call the Microsoft Graph API to get conditional access policies
        $caApi = if([string]::IsNullOrEmpty($TenantId)) { "identity/conditionalAccess/policies" } else { "identity/conditionalAccess/policies/$TenantId" }
        $caResponse = Call-MSGraphAPI -AccessToken $AccessToken -API $caApi -ApiVersion "v1.0"
        return $caResponse
    }
}

# Aug 25th 2025
function Get-MSGraphOrganization
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$TenantId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "d3590ed6-52b3-4102-aeff-aad2292ab01c" -Resource "https://graph.microsoft.com"

        # Call the Microsoft Graph API to get organization information
        $orgApi = if([string]::IsNullOrEmpty($TenantId)) { "organization" } else { "organization/$TenantId" }
        $orgResponse = Call-MSGraphAPI -AccessToken $AccessToken -API $orgApi -ApiVersion "v1.0"
        return $orgResponse
    }
}

# Aug 25th 2025
function Get-MSGraphRootSite
{
<#
    .SYNOPSIS
    Gets the SharePoint root site via Microsoft Graph.

    .DESCRIPTION
    Calls Microsoft Graph v1.0 endpoint /sites/root and returns the site object.

    .PARAMETER AccessToken
    Optional access token for https://graph.microsoft.com. Retrieved from cache if not provided.

    .EXAMPLE
    Get-MSGraphRootSite | Select-Object id, webUrl
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        $results = Call-MSGraphAPI -AccessToken $AccessToken -API "sites/root" -ApiVersion "v1.0"

        return $results
    }
}

# Aug 25th 2025
function Get-MSGraphDirectoryRoles
{
<#
    .SYNOPSIS
    Lists active directory roles and their members using Microsoft Graph.

    .DESCRIPTION
    Retrieves active Azure AD directory roles (directoryRoles) and, for each, fetches members.
    Returns objects shaped similar to legacy Get-Roles + Get-RoleMembers output:
      Name, IsEnabled, IsSystem, ObjectId (roleTemplateId), Members (DisplayName, UserPrincipalName).

    .PARAMETER AccessToken
    Optional access token for https://graph.microsoft.com. Retrieved from cache if not provided.

    .EXAMPLE
    Get-MSGraphDirectoryRoles | Where-Object Members -ne $null | Select-Object Name,Members
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        # Get active directory roles (only activated roles are returned)
        $roles = Call-MSGraphAPI -AccessToken $AccessToken -API "directoryRoles" -ApiVersion "v1.0" -QueryString "`$select=id,displayName,roleTemplateId"

        $roleInformation = @()
        foreach($role in ($roles | Sort-Object -Property displayName))
        {
            # Fetch role members; may include users, groups, service principals
            $members = @()
            try { $members = @(Get-MSGraphRoleMembers -AccessToken $AccessToken -RoleId $role.id) } catch {}

            $attributes = [ordered]@{
                Name       = $role.displayName
                IsEnabled  = $true
                IsSystem   = $true
                # Use roleTemplateId to match legacy fixed GUIDs like Global Admin (62e90394-...)
                ObjectId   = $role.roleTemplateId
                Members    = $members
            }

            $roleInformation += (New-Object psobject -Property $attributes)
        }

        return $roleInformation
    }
}

# Aug 26th 2025
function Get-MSGraphPartnerContracts
{
<#
    .SYNOPSIS
    Lists partner contracts for the current tenant via Microsoft Graph.

    .DESCRIPTION
    Calls GET /v1.0/contracts and returns the collection. In a partner tenant, this lists
    customer contracts. In a customer tenant, this lists partner contracts.

    .PARAMETER AccessToken
    Optional access token for https://graph.microsoft.com. Retrieved from cache if not provided.

    .EXAMPLE
    Get-MSGraphPartnerContracts | Select-Object contractType, customerId, defaultDomainName
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        $results = Call-MSGraphAPI -AccessToken $AccessToken -API "contracts" -ApiVersion "v1.0"
        return $results
    }
}

# Aug 26th 2025
function Get-MSGraphDelegatedAdminCustomers
{
<#
    .SYNOPSIS
    Lists delegated admin customers (GDAP/DAP relationships) for a partner tenant.

    .DESCRIPTION
    Calls GET /v1.0/tenantRelationships/delegatedAdminCustomers to return customer tenants
    that have a delegated admin relationship with the current tenant (partner).

    .PARAMETER AccessToken
    Optional access token for https://graph.microsoft.com. Retrieved from cache if not provided.

    .EXAMPLE
    Get-MSGraphDelegatedAdminCustomers | Select-Object id, displayName, tenantId
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        $results = Call-MSGraphAPI -AccessToken $AccessToken -API "tenantRelationships/delegatedAdminCustomers" -ApiVersion "v1.0"
        return $results
    }
}

# Aug 26th 2025
function Get-MSGraphDelegatedAdminRelationships
{
<#
    .SYNOPSIS
    Lists delegated admin relationships (GDAP) and optionally access assignments with names.

    .DESCRIPTION
    - GET /v1.0/tenantRelationships/delegatedAdminRelationships
    - If -IncludeAssignments, fetches /tenantRelationships/delegatedAdminRelationships/{id}/accessAssignments
    - If -ResolveNames, resolves roleDefinitionId to displayName and group id to displayName

    .PARAMETER AccessToken
    Optional access token for https://graph.microsoft.com. Retrieved from cache if not provided.

    .PARAMETER IncludeAssignments
    When set, include access assignments for each relationship.

    .PARAMETER ResolveNames
    When set with IncludeAssignments, resolves role names and group display names.

    .EXAMPLE
    Get-MSGraphDelegatedAdminRelationships -IncludeAssignments -ResolveNames
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [switch]$IncludeAssignments,
        [switch]$ResolveNames
    )
    Process
    {
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        $relationships = Call-MSGraphAPI -AccessToken $AccessToken -API "tenantRelationships/delegatedAdminRelationships" -ApiVersion "v1.0"

        if(-not $IncludeAssignments){ return $relationships }

        # Prepare optional maps for resolving names
        $roleMap = @{}
        if($ResolveNames){
            try {
                $defs = Call-MSGraphAPI -AccessToken $AccessToken -API "roleManagement/directory/roleDefinitions" -ApiVersion "v1.0" -QueryString "`$select=id,displayName"
                foreach($d in $defs){ if($d.id){ $roleMap[$d.id] = $d.displayName } }
            } catch {}
        }

        $out = @()
        foreach($rel in $relationships){
            $assignments = @()
            try {
                $as = Call-MSGraphAPI -AccessToken $AccessToken -API "tenantRelationships/delegatedAdminRelationships/$($rel.id)/accessAssignments" -ApiVersion "v1.0"
                foreach($a in $as){
                    $groupName = $null
                    if($ResolveNames -and $a.accessContainer -and $a.accessContainer.type -eq "securityGroup" -and $a.accessContainer.externalId){
                        try {
                            $g = Call-MSGraphAPI -AccessToken $AccessToken -API "groups/$($a.accessContainer.externalId)" -ApiVersion "v1.0" -QueryString "`$select=id,displayName"
                            $groupName = $g.displayName
                        } catch {}
                    }

                    # Resolve unified role display names if requested
                    $roles = @()
                    if($a.accessDetails -and $a.accessDetails.unifiedRoles){
                        foreach($r in $a.accessDetails.unifiedRoles){
                            if($ResolveNames -and $roleMap.ContainsKey($r.roleDefinitionId)){
                                $roles += $roleMap[$r.roleDefinitionId]
                            } else {
                                $roles += $r.roleDefinitionId
                            }
                        }
                    }

                    $assignments += [pscustomobject]@{
                        id                = $a.id
                        accessContainer   = $a.accessContainer
                        groupDisplayName  = $groupName
                        roles             = $roles
                        accessDetails     = $a.accessDetails
                        status            = $a.status
                        createdDateTime   = $a.createdDateTime
                        lastModifiedDateTime = $a.lastModifiedDateTime
                    }
                }
            } catch {}

            $o = [pscustomobject]@{
                id                    = $rel.id
                displayName           = $rel.displayName
                status                = $rel.status
                customerTenantId      = $rel.customer.tenantId
                createdDateTime       = $rel.createdDateTime
                endDateTime           = $rel.endDateTime
                accessAssignments     = $assignments
            }
            $out += $o
        }

        return $out
    }
}

# Aug 26th 2025
function Get-MSGraphIdentitySecurityDefaultsPolicy
{
<#
    .SYNOPSIS
    Gets the Identity Security Defaults Enforcement Policy via Microsoft Graph.

    .DESCRIPTION
    Calls Microsoft Graph v1.0 endpoint /policies/identitySecurityDefaultsEnforcementPolicy and returns the policy object.

    .PARAMETER AccessToken
    Optional access token for https://graph.microsoft.com. Retrieved from cache if not provided.

    .EXAMPLE
    Get-MSGraphIdentitySecurityDefaultsPolicy | Select-Object id, displayName, isEnabled
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        $results = Call-MSGraphAPI -AccessToken $AccessToken -API "policies/identitySecurityDefaultsEnforcementPolicy" -ApiVersion "v1.0"
        return $results
    }
}

# Aug 26th 2025
function Get-MSGraphSubscribedSkus
{
<#
    .SYNOPSIS
    Gets the tenant's subscribed SKUs via Microsoft Graph.

    .DESCRIPTION
    Calls Microsoft Graph v1.0 endpoint /subscribedSkus and returns the collection of subscribedSku objects.

    .PARAMETER AccessToken
    Optional access token for https://graph.microsoft.com. Retrieved from cache if not provided.

    .EXAMPLE
    Get-MSGraphSubscribedSkus | Select-Object skuId, skuPartNumber, consumedUnits
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        $results = Call-MSGraphAPI -AccessToken $AccessToken -API "subscribedSkus" -ApiVersion "v1.0"
        return $results
    }
}

function Get-MSGraphAccessPackages
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        # Retrieve all access packages
        $accessPackages = Call-MSGraphAPI -AccessToken $AccessToken -API "identityGovernance/entitlementManagement/accessPackages" -ApiVersion "v1.0"

        $results = @()

        foreach ($package in $accessPackages.value) {
            # Get assignment policies for each package
            $policies = Call-MSGraphAPI -AccessToken $AccessToken -API "identityGovernance/entitlementManagement/accessPackages/$($package.id)/accessPackageAssignmentPolicies" -ApiVersion "v1.0"

            $results += [PSCustomObject]@{
                Id                = $package.id
                DisplayName       = $package.displayName
                Description       = $package.description
                CreatedDateTime   = $package.createdDateTime
                IsHidden          = $package.isHidden
                AssignmentPolicies = $policies.value
            }
        }

        return $results
    }
}

function Get-MSGraphAdministrativeUnits
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        # Retrieve all administrative units
        $administrativeUnits = Call-MSGraphAPI -AccessToken $AccessToken -API "directory/administrativeUnits" -ApiVersion "v1.0"

        foreach ($au in $administrativeUnits) {
            # Retrieve scoped role assignments for this AU
            $roleAssignments = Call-MSGraphAPI -AccessToken $AccessToken -API "directory/administrativeUnits/$($au.id)/scopedRoleMembers" -ApiVersion "v1.0"

            # Attach role assignments to AU object
            $au | Add-Member -NotePropertyName "ScopedRoleAssignments" -NotePropertyValue $roleAssignments.value -Force
        }

        return $administrativeUnits
    }
}

# This script contains functions for MSGraph API at https://graph.microsoft.com

# Get the provisioning events that occurred in your tenant
# Jul 16 2022
function Get-MSGraphProvisioningEvents
{
    <#
    .SYNOPSIS
    Get the provisioning events that occurred in your tenant

    .DESCRIPTION
    Get the provisioning events that occurred in your tenant
    See https://docs.microsoft.com/en-us/graph/api/provisioningobjectsummary-list?view=graph-rest-1.0&tabs=http.

    .PARAMETER AccessToken
    Access token used to get the provisioning events that occurred in your tenant

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphProvisioningEvents -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $False)]
        [String]$EntryId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        # Select one entry if provided
        if ($EntryId)
        {
            $queryString = "`$filter=id eq '$EntryId'"
        }
        else
        {
            $queryString = "`$orderby=activityDateTime"
        }

        Call-MSGraphAPI -AccessToken $AccessToken -API "auditLogs/provisioning" -ApiVersion "v1.0" -QueryString $queryString
    }
}

# Gets the user's data
# Jun 23th 2022
function Get-MSGraphUsers
{
    <#
    .SYNOPSIS
    Returns the users.

    .DESCRIPTION
    Returns the users. You can also search for a specific user by displayName or userPrincipalName.

    .PARAMETER AccessToken
    Access token used to get the users

    .PARAMETER SearchString
    Search parameter for displayName or userPrincipalName

    .PARAMETER UserPrincipalName
    Return only the selected userPrincipalName's data

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphUsers -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $False)]
        [String]$SearchString,
        [Parameter(Mandatory = $False)]
        [String]$UserPrincipalName
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        if (![string]::IsNullOrEmpty($SearchString))
        {
            $queryString = "&`$filter=(startswith(displayName,'$SearchString') or startswith(userPrincipalName,'$SearchString'))"
        }
        elseif (![string]::IsNullOrEmpty($UserPrincipalName))
        {
            $queryString = "&`$filter=userPrincipalName eq '$UserPrincipalName'"
        }

        Call-MSGraphAPI -AccessToken $AccessToken -API "users" -ApiVersion v1.0 -QueryString "`$select=businessPhones,displayName,givenName,id,jobTitle,mail,mobilePhone,officeLocation,preferredLanguage,surname,userPrincipalName,onPremisesDistinguishedName,onPremisesExtensionAttributes,onPremisesImmutableId,onPremisesLastSyncDateTime,onPremisesSamAccountName,onPremisesSecurityIdentifier,refreshTokensValidFromDateTime,signInSessionsValidFromDateTime,usageLocation,provisionedPlans,proxyAddresses$queryString"
    }
}

# Gets the current user data
# Jul 1th 2022
function Get-MSGraphPersonalUser
{
    <#
    .SYNOPSIS
    Returns the current user.

    .DESCRIPTION
    Returns the current user.

    .PARAMETER AccessToken
    Access token used to get the current user

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphPersonalUser -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "me" -ApiVersion "v1.0" -QueryString "`$select=businessPhones,displayName,givenName,id,jobTitle,mail,mobilePhone,officeLocation,preferredLanguage,surname,userPrincipalName,onPremisesDistinguishedName,onPremisesExtensionAttributes,onPremisesImmutableId,onPremisesLastSyncDateTime,onPremisesSamAccountName,onPremisesSecurityIdentifier,refreshTokensValidFromDateTime,signInSessionsValidFromDateTime,usageLocation,provisionedPlans,proxyAddresses"
    }
}

# Gets an user data
# Jul 1th 2022
function Get-MSGraphUser
{
    <#
    .SYNOPSIS
    Returns an user.

    .DESCRIPTION
    Returns an user.

    .PARAMETER AccessToken
    Access token used to get the user

    .PARAMETER UserId
    User identifier or principal name

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphUser -UserId "39429de5-4135-4ec3-ac2b-884f79b7ad5d" -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$UserId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserId" -ApiVersion "v1.0" -QueryString "`$select=businessPhones,displayName,givenName,id,jobTitle,mail,mobilePhone,officeLocation,preferredLanguage,surname,userPrincipalName,onPremisesDistinguishedName,onPremisesExtensionAttributes,onPremisesImmutableId,onPremisesLastSyncDateTime,onPremisesSamAccountName,onPremisesSecurityIdentifier,refreshTokensValidFromDateTime,signInSessionsValidFromDateTime,usageLocation,provisionedPlans,proxyAddresses"
    }
}

# Gets the user's application role assignments
# Jul 22nd 2022
function Get-MSGraphUserAppRoleAssignments
{
    <#
    .SYNOPSIS
    Returns an user application role assignments.

    .DESCRIPTION
    Returns an user application role assignments.

    .PARAMETER AccessToken
    Access token used to get the user application role assignments

    .PARAMETER UserId
    User identifier or principal name

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphUserAppRoleAssignments -UserId "64d999db-fc15-459c-bccf-5fa5908557aa" -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $False)]
        [String]$UserId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserId/appRoleAssignments" -ApiVersion v1.0
    }
}

# Gets the user's owned devices
# Jun 16th 2020
function Get-MSGraphUserOwnedDevices
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $False)]
        [String]$UserPrincipalName
    )
    Process
    {
        # Url encode for external users, replace # with %23
        $UserPrincipalName = $UserPrincipalName.Replace("#", "%23")

        $results = Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserPrincipalName/ownedDevices" -ApiVersion v1.0

        return $results
    }
}

# Gets the user's licenses
# Jun 16th 2020
function Get-MSGraphUserLicenseDetails
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $False)]
        [String]$UserPrincipalName
    )
    Process
    {
        # Url encode for external users, replace # with %23
        $UserPrincipalName = $UserPrincipalName.Replace("#", "%23")

        $results = Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserPrincipalName/licenseDetails" -ApiVersion v1.0 

        return $results
    }
}

# Gets the current user's direct reports
# Jul 21th 2022
function Get-MSGraphPersonalDirectReports
{
    <#
    .SYNOPSIS
    Returns the current user direct reports.

    .DESCRIPTION
    Returns the current user direct reports.

    .PARAMETER AccessToken
    Access token used to get the current user direct reports

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphPersonalDirectReports -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "me/directReports" -ApiVersion v1.0 -QueryString "`$select=businessPhones,displayName,givenName,id,jobTitle,mail,mobilePhone,officeLocation,preferredLanguage,surname,userPrincipalName,onPremisesDistinguishedName,onPremisesExtensionAttributes,onPremisesImmutableId,onPremisesLastSyncDateTime,onPremisesSamAccountName,onPremisesSecurityIdentifier,refreshTokensValidFromDateTime,signInSessionsValidFromDateTime,usageLocation,provisionedPlans,proxyAddresses"
    }
}

# Gets the user's direct reports
# Jun 16th 2020
function Get-MSGraphUserDirectReports
{
    <#
    .SYNOPSIS
    Returns an user direct reports.

    .DESCRIPTION
    Returns an user direct reports.

    .PARAMETER AccessToken
    Access token used to get the user direct reports

    .PARAMETER UserId
    User identifier or principal name

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphUserDirectReports -UserId "39429de5-4135-4ec3-ac2b-884f79b7ad5d" -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$UserId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserId/directReports" -ApiVersion v1.0 -QueryString "`$select=businessPhones,displayName,givenName,id,jobTitle,mail,mobilePhone,officeLocation,preferredLanguage,surname,userPrincipalName,onPremisesDistinguishedName,onPremisesExtensionAttributes,onPremisesImmutableId,onPremisesLastSyncDateTime,onPremisesSamAccountName,onPremisesSecurityIdentifier,refreshTokensValidFromDateTime,signInSessionsValidFromDateTime,usageLocation,provisionedPlans,proxyAddresses"
    }
}

# Gets the current user's manager
# Jul 21th 2022
function Get-MSGraphPersonalManager
{
    <#
    .SYNOPSIS
    Returns the current user manager.

    .DESCRIPTION
    Returns the current user manager.

    .PARAMETER AccessToken
    Access token used to get the current user manager

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphPersonalManager -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "me/manager" -ApiVersion v1.0 -QueryString "`$select=businessPhones,displayName,givenName,id,jobTitle,mail,mobilePhone,officeLocation,preferredLanguage,surname,userPrincipalName,onPremisesDistinguishedName,onPremisesExtensionAttributes,onPremisesImmutableId,onPremisesLastSyncDateTime,onPremisesSamAccountName,onPremisesSecurityIdentifier,refreshTokensValidFromDateTime,signInSessionsValidFromDateTime,usageLocation,provisionedPlans,proxyAddresses"
    }
}

# Gets the user's manager
# Jun 16th 2020
function Get-MSGraphUserManager
{
    <#
    .SYNOPSIS
    Returns an user manager.

    .DESCRIPTION
    Returns an user manager.

    .PARAMETER AccessToken
    Access token used to get the user manager

    .PARAMETER UserId
    User identifier or principal name

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphUserManager -UserId "64d999db-fc15-459c-bccf-5fa5908557aa" -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $False)]
        [String]$UserId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserId/manager" -ApiVersion v1.0 -QueryString "`$select=businessPhones,displayName,givenName,id,jobTitle,mail,mobilePhone,officeLocation,preferredLanguage,surname,userPrincipalName,onPremisesDistinguishedName,onPremisesExtensionAttributes,onPremisesImmutableId,onPremisesLastSyncDateTime,onPremisesSamAccountName,onPremisesSecurityIdentifier,refreshTokensValidFromDateTime,signInSessionsValidFromDateTime,usageLocation,provisionedPlans,proxyAddresses"
    }
}

# Gets the group's owners
# Jun 16th 2020
function Get-MSGraphGroupOwners
{
    <#
    .SYNOPSIS
    Returns the group owners.

    .DESCRIPTION
    Returns the group owners.

    .PARAMETER AccessToken
    Access token used to get the group owners

    .PARAMETER GroupId
    Group identifier

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphGroups -AccessToken $AccessToken # get an identifier
    PS C:\>Get-AADIntMSGraphGroupOwners -AccessToken $AccessToken -GroupId 2c150da4-603f-4348-a886-624f8aaf4b49
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$GroupId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "groups/$GroupId/owners" -ApiVersion v1.0 -QueryString "`$select=businessPhones,displayName,givenName,id,jobTitle,mail,mobilePhone,officeLocation,preferredLanguage,surname,userPrincipalName,onPremisesDistinguishedName,onPremisesExtensionAttributes,onPremisesImmutableId,onPremisesLastSyncDateTime,onPremisesSamAccountName,onPremisesSecurityIdentifier,refreshTokensValidFromDateTime,signInSessionsValidFromDateTime,usageLocation,provisionedPlans,proxyAddresses"
    }
}

# Gets the group's members
# Jun 16th 2020
function Get-MSGraphGroupMembers
{
    <#
    .SYNOPSIS
    Returns the group members.

    .DESCRIPTION
    Returns the group members. A group can have users, organizational contacts, devices, service principals and other groups as members.
    See https://docs.microsoft.com/en-us/graph/api/group-list-members?view=graph-rest-1.0&tabs=http.

    .PARAMETER AccessToken
    Access token used to get the group members

    .PARAMETER GroupId
    Group identifier

    .PARAMETER ApiVersion
    Optional. Set to v1.0 by default.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphGroups -AccessToken $AccessToken # get an identifier
    PS C:\>Get-AADIntMSGraphGroupMembers -AccessToken $AccessToken -GroupId 2c150da4-603f-4348-a886-624f8aaf4b49
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$GroupId,
        [Parameter(Mandatory = $False)]
        [String]$ApiVersion = "v1.0"
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "groups/$GroupId/members" -ApiVersion $ApiVersion -QueryString "`$top=500&`$select=businessPhones,displayName,givenName,id,jobTitle,mail,mobilePhone,officeLocation,preferredLanguage,surname,userPrincipalName,onPremisesDistinguishedName,onPremisesExtensionAttributes,onPremisesImmutableId,onPremisesLastSyncDateTime,onPremisesSamAccountName,onPremisesSecurityIdentifier,refreshTokensValidFromDateTime,signInSessionsValidFromDateTime,usageLocation,provisionedPlans,proxyAddresses"
    }
}

# Gets the group's permission grants
# Jul 22nd 2022
function Get-MSGraphGroupPermissionGrants
{
    <#
    .SYNOPSIS
    Returns the group permission grants.

    .DESCRIPTION
    Returns the group permission grants.

    .PARAMETER AccessToken
    Access token used to get the group permission grants

    .PARAMETER GroupId
    Group identifier

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphGroups -AccessToken $AccessToken # get an identifier
    PS C:\>Get-AADIntMSGraphGroupPermissionGrants -AccessToken $AccessToken -GroupId 2c150da4-603f-4348-a886-624f8aaf4b49
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$GroupId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "groups/$GroupId/permissionGrants" -ApiVersion v1.0
    }
}

# Gets the directory roles
# Jul 22nd 2022
function Get-MSGraphRoles
{
    <#
    .SYNOPSIS
    Returns the directory roles.

    .DESCRIPTION
    Returns the directory roles. This operation only returns roles that have been activated.
    See https://docs.microsoft.com/en-us/graph/api/directoryrole-list?view=graph-rest-1.0&tabs=http.

    .PARAMETER AccessToken
    Access token used to get the directory roles

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphRoles -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "directoryRoles" -ApiVersion v1.0
    }
}

# Gets the role's members
# Jun 17th 2020
function Get-MSGraphRoleMembers
{
    <#
    .SYNOPSIS
    Returns the role members.

    .DESCRIPTION
    Returns the role members. Usually fails.

    .PARAMETER AccessToken
    Access token used to get the role members

    .PARAMETER RoleId
    Role identifier

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphUserMemberOf -AccessToken $AccessToken -UserId 64d999db-fc15-459c-bccf-5fa5908557aa # get a role identifier
    PS C:\>Get-AADIntMSGraphRoleMembers -AccessToken $AccessToken -RoleId 40edd42d-2b58-4f1b-a628-d99eac621948
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$RoleId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "directoryRoles/$RoleId/members" -ApiVersion v1.0 -QueryString "`$select=businessPhones,displayName,givenName,id,jobTitle,mail,mobilePhone,officeLocation,preferredLanguage,surname,userPrincipalName,onPremisesDistinguishedName,onPremisesExtensionAttributes,onPremisesImmutableId,onPremisesLastSyncDateTime,onPremisesSamAccountName,onPremisesSecurityIdentifier,refreshTokensValidFromDateTime,signInSessionsValidFromDateTime,usageLocation,provisionedPlans,proxyAddresses"
    }
}

# Gets the role scoped members
# Jul 22nd 2022
function Get-MSGraphRoleScopedMembers
{
    <#
    .SYNOPSIS
    Returns the role scoped members.

    .DESCRIPTION
    Returns the role scoped members.

    .PARAMETER AccessToken
    Access token used to get the role scoped members

    .PARAMETER RoleId
    Role identifier

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphUserMemberOf -AccessToken $AccessToken -UserId 64d999db-fc15-459c-bccf-5fa5908557aa # get a role identifier
    PS C:\>Get-AADIntMSGraphRoleScopedMembers -AccessToken $AccessToken -RoleId 40edd42d-2b58-4f1b-a628-d99eac621948
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$RoleId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "directoryRoles/$RoleId/scopedMembers" -ApiVersion v1.0
    }
}

# Gets the tenant domains
# Jun 16th 2020
function Get-MSGraphDomains
{
    <#
    .SYNOPSIS
    Gets tenant's domains

    .DESCRIPTION
    Gets tenant's domains

    .PARAMETER AccessToken
    Access token used to retrieve the domains

    .Example
    PS C:\>Get-AADIntMSGraphDomains -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "domains" -ApiVersion beta
    }
}

# Gets a domain
# Jul 22nd 2022
function Get-MSGraphDomain
{
    <#
    .SYNOPSIS
    Get a domain

    .DESCRIPTION
    Get a domain

    .PARAMETER AccessToken
    Access token used to retrieve a domain 

    .PARAMETER DomainId
    Domain identifier

    .Example
    PS C:\>Get-AADIntMSGraphDomain -AccessToken $AccessToken -DomainId "contoso.com"
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$DomainId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "domains/$DomainId" -ApiVersion beta
    }
}

# Gets the domain name references 
# Jul 22nd 2022
function Get-MSGraphDomainNameReferences
{
    <#
    .SYNOPSIS
    Get the domain name references

    .DESCRIPTION
    Get the domain name references

    .PARAMETER AccessToken
    Access token used to retrieve the domain name references 

    .PARAMETER DomainId
    Domain identifier

    .Example
    PS C:\>Get-AADIntMSGraphDomainNameReferences -AccessToken $AccessToken -DomainId "contoso.com"
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$DomainId,
        [Parameter(Mandatory = $False)]
        [bool]$OnlyGroups,
        [Parameter(Mandatory = $False)]
        [bool]$OnlyUsers
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        if ($OnlyGroups) {
            Call-MSGraphAPI -AccessToken $AccessToken -API "domains/$DomainId/domainNameReferences/microsoft.graph.group" -ApiVersion beta
        } elseif ($OnlyUsers) {
            Call-MSGraphAPI -AccessToken $AccessToken -API "domains/$DomainId/domainNameReferences/microsoft.graph.user" -ApiVersion beta
        } else {
            Call-MSGraphAPI -AccessToken $AccessToken -API "domains/$DomainId/domainNameReferences" -ApiVersion beta
        }
    }
}

# Gets the domain service configuration records
# Jul 22nd 2022
function Get-MSGraphDomainServiceConfigurationRecords
{
    <#
    .SYNOPSIS
    Get the domain service configuration records

    .DESCRIPTION
    Get the domain service configuration records

    .PARAMETER AccessToken
    Access token used to retrieve the domain service configuration records 

    .PARAMETER DomainId
    Domain identifier

    .Example
    PS C:\>Get-AADIntMSGraphDomainServiceConfigurationRecords -AccessToken $AccessToken -DomainId "contoso.com"
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$DomainId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "domains/$DomainId/serviceConfigurationRecords" -ApiVersion beta
    }
}

# Gets the domain verification DNS records
# Jul 22nd 2022
function Get-MSGraphDomainVerificationDNSRecords
{
    <#
    .SYNOPSIS
    Get the domain verification DNS records

    .DESCRIPTION
    Get the domain verification DNS records

    .PARAMETER AccessToken
    Access token used to retrieve the domain verification DNS records 

    .PARAMETER DomainId
    Domain identifier

    .Example
    PS C:\>Get-AADIntMSGraphDomainVerificationDNSRecords -AccessToken $AccessToken -DomainId "contoso.com"
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$DomainId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "domains/$DomainId/verificationDnsRecords" -ApiVersion beta
    }
}

# Gets team information
# Jun 17th 2020
function Get-MSGraphTeam
{
    <#
    .SYNOPSIS
    Returns the teams informations.

    .DESCRIPTION
    Returns the teams informations. Return (404) Not Found if the group is not a team.
    Return (403) Forbidden if the user is unprivileged.
    See https://docs.microsoft.com/en-us/graph/api/team-get?view=graph-rest-beta&tabs=http.

    .PARAMETER AccessToken
    Access token used to get the team information.

    .PARAMETER GroupId
    Group identifier

    .PARAMETER ApiVersion
    Optional. Set to beta by default to retrieve more results.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphGroups -AccessToken $AccessToken # get an identifier
    PS C:\>Get-AADIntMSGraphTeam -AccessToken $AccessToken -GroupId aa9ea6fd-6b09-4b70-9ba6-34551068a8d0
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$GroupId,
        [Parameter(Mandatory = $False)]
        [String]$ApiVersion = "beta"
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "teams/$GroupId" -ApiVersion $ApiVersion
    }
}

# Gets team members
# Jun 17th 2020
function Get-MSGraphTeamMembers
{
    <#
    .SYNOPSIS
    Returns the teams members.

    .DESCRIPTION
    Returns the teams members. Return (404) Not Found if the group is not a team.
    Return (403) Forbidden if the user is unprivileged.
    See https://docs.microsoft.com/en-us/graph/api/team-get?view=graph-rest-beta&tabs=http.

    .PARAMETER AccessToken
    Access token used to get the team information.

    .PARAMETER GroupId
    Group identifier

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphGroups -AccessToken $AccessToken # get an identifier
    PS C:\>Get-AADIntMSGraphTeamMembers -AccessToken $AccessToken -GroupId aa9ea6fd-6b09-4b70-9ba6-34551068a8d0
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$GroupId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "teams/$GroupId/members"
    }
}

# Gets team's app information
# Jun 17th 2020
function Get-MSGraphTeamsApps
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$GroupId
    )
    Process
    {
        $results = Call-MSGraphAPI -AccessToken $AccessToken -API "teams/$GroupId/installedApps?`$expand=teamsAppDefinition" -ApiVersion v1.0

        return $results
    }
}


# Get the root drive
# Jun 1s 2022
function Get-MSGraphPersonalRootFolder
{
    <#
    .SYNOPSIS
    Get the root drive.

    .DESCRIPTION
    Get the root drive.

    .PARAMETER AccessToken
    Access token used to get the root drive.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphPersonalRootFolder -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894 "

        Call-MSGraphAPI -AccessToken $AccessToken -API "me/drive/root" -ApiVersion "v1.0"
    }
}

# Get the personal drive items
# Jun 1st 2022
function Get-MSGraphPersonalDriveItems
{
    <#
    .SYNOPSIS
    Get the root drive items.

    .DESCRIPTION
    Get the root drive items.

    .PARAMETER AccessToken
    Access token used to get the root drive items.

    .PARAMETER DriveId
    Drive identifier.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphPersonalDriveItems -DriveId "017F7BVQF6Y2GOVW7725BZO354PWSELRRZ" -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$DriveId,
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $False)]
        [int]$MaxResults = 1000
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -MaxResults $MaxResults -AccessToken $AccessToken -API "me/drive/items/$DriveId/children" -ApiVersion "v1.0"
    }
}

# Get the personal drive items content
# Jun 1st 2022
function Get-MSGraphPersonalDriveItemsContent
{
    <#
    .SYNOPSIS
    Get the drive items content.

    .DESCRIPTION
    Get recursively the drive items content i.e. name, download URL, etc.

    .PARAMETER AccessToken
    Access token used to get the drive items content.

    .PARAMETER RootDriveId
    Root drive identifier.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>$data = Get-AADIntMSGraphPersonalDriveItemsContent -AccessToken $AccessToken
    PS C:\>$data.'@microsoft.graph.downloadUrl'
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [string]$RootDriveId,
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $False)]
        [int]$MaxResults = 1000
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        if ([string]::IsNullOrEmpty($RootDriveId))
        {
            $RootDrive = Get-MSGraphPersonalRootFolder -AccessToken $AccessToken
            $RootDriveId = $RootDrive.id
            # Return
            $RootDrive
        }

        if ([string]::IsNullOrEmpty($RootDriveId))
        {
            Write-Error "`$RootDriveId is empty. We couldn't get it with Get-MSGraphGroupRootFolder."
            return
        }
        
        # Get the files and folders in the root drive
        $CurrentDrive = Get-MSGraphPersonalDriveItems -MaxResults $MaxResults -DriveId $RootDriveId -AccessToken $AccessToken

        # return
        $CurrentDrive

        foreach ($file in $CurrentDrive)
        {
            Write-Verbose "File or folder name : ""$($file.name)"""

            if ($null -eq $file.folder)
            {
                continue
            }
            
            Get-MSGraphPersonalDriveItemsContent -MaxResults $MaxResults -RootDriveId "$($file.id)" -AccessToken $AccessToken
        }
    }
}

# Gets groups information
# Jun 1st 2022
function Get-MSGraphGroups
{
    <#
    .SYNOPSIS
    Get the groups.

    .DESCRIPTION
    Get the groups.

    .PARAMETER AccessToken
    Access token used to get the groups.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphGroups -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "groups" -ApiVersion v1.0
    }
}

# Gets M365 groups information
# 9/4/2025
function Get-MSGraphM365Groups
{
    <#
    .SYNOPSIS
    Get the M365 groups.

    .DESCRIPTION
    Get the M365 groups.

    .PARAMETER AccessToken
    Access token used to get the groups.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphM365Groups -AccessToken $AccessToken
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "groups" -ApiVersion v1.0 -QueryString "`$filter=groupTypes/any(c:c eq 'Unified')"
    }
}

# Gets groups that contains a team.
# Jun 1st 2022
function Get-MSGraphGroupsWithTeam
{
    <#
    .SYNOPSIS
    Get the groups that contains a team.

    .DESCRIPTION
    Get the groups that contains a team.
    See https://docs.microsoft.com/fr-fr/graph/teams-list-all-teams#example-1-get-list-of-groups-that-contain-a-team and
    https://docs.microsoft.com/en-us/graph/group-set-options.

    .PARAMETER AccessToken
    Access token used to get the groups.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphGroupsWithTeam -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "groups" -ApiVersion v1.0 -QueryString "`$filter=resourceProvisioningOptions/Any(x:x eq 'Team')"
    }
}

# Gets groups drives
# Jun 1st 2022
function Get-MSGraphGroupDrives
{
    <#
    .SYNOPSIS
    Get the group drives.

    .DESCRIPTION
    Get the group drives.

    .PARAMETER AccessToken
    Access token used to get the group drives.

    .PARAMETER GroupId
    Group identifier.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphGroupDrives -GroupId "0fdc2543-0516-4b79-a017-a70a54f4d57d" -AccessToken $AccessToken
    PS C:\>Get-AADIntMSGraphGroupDrives -GroupId "0fdc2543-0516-4b79-a017-a70a54f4d57d" -AccessToken $AccessToken | Select-Object -expandProperty owner
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [GUID]$GroupId,
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $False)]
        [int]$MaxResults = 1000
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -MaxResults $MaxResults -AccessToken $AccessToken -API "groups/$($GroupId.ToString())/drives" -ApiVersion v1.0
    }
}

# Get the root drive of the group
# Jun 1s 2022
function Get-MSGraphGroupRootFolder
{
    <#
    .SYNOPSIS
    Get the root drive of the group.

    .DESCRIPTION
    Get the root drive of the group.

    .PARAMETER AccessToken
    Access token used to get the root drive of the group.

    .PARAMETER GroupId
    Group identifier.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphGroupRootFolder -GroupId "0fdc2543-0516-4b79-a017-a70a54f4d57d" -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [GUID]$GroupId,
        [Parameter(Mandatory = $False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "groups/$($GroupId.ToString())/drive/root" -ApiVersion "v1.0"
    }
}

# Get the group drive items
# Jun 1st 2022
function Get-MSGraphGroupDriveItems
{
    <#
    .SYNOPSIS
    Get the root drive items of the group.

    .DESCRIPTION
    Get the root drive items of the group.

    .PARAMETER AccessToken
    Access token used to get the root drive items of the group.

    .PARAMETER DriveId
    Drive identifier.

    .PARAMETER GroupId
    Group identifier.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphGroupDriveItems -GroupId "0fdc2543-0516-4b79-a017-a70a54f4d57d" -DriveId "01U74I73N6Y2GOVW7725BZO354PWSELRRZ" -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [GUID]$GroupId,
        [Parameter(Mandatory = $True)]
        [String]$DriveId,
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $False)]
        [int]$MaxResults = 1000
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -MaxResults $MaxResults -AccessToken $AccessToken -API "groups/$($GroupId.ToString())/drive/items/$DriveId/children" -ApiVersion "v1.0"
    }
}

# Get the group drive items content
# Jun 1st 2022
function Get-MSGraphGroupDriveItemsContent
{
    <#
    .SYNOPSIS
    Get the drive items content.

    .DESCRIPTION
    Get recursively the drive items content i.e. name, download URL, etc.

    .PARAMETER AccessToken
    Access token used to get the drive items content.

    .PARAMETER RootDriveId
    Root drive identifier.

    .PARAMETER GroupId
    Group identifier.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>$data = Get-AADIntMSGraphGroupDriveItemsContent -GroupId "0fdc2543-0516-4b79-a017-a70a54f4d57d" -AccessToken $AccessToken
    PS C:\>$data.'@microsoft.graph.downloadUrl'
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [GUID]$GroupId,
        [Parameter(Mandatory = $False)]
        [string]$RootDriveId,
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $False)]
        [int]$MaxResults = 1000
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        if ([string]::IsNullOrEmpty($RootDriveId))
        {
            try {
                $RootDrive = Get-MSGraphGroupRootFolder -GroupId $GroupId -AccessToken $AccessToken -ErrorAction Stop
                $RootDriveId = $RootDrive.id
                # Return
                $RootDrive
            }
            catch {
                $msg = $_.Exception.Message
                if ($msg -match 'Access denied' -or $msg -match 'Resource is not found\.') {
                    Write-Verbose "Group ${GroupId}: $msg (skipping)"
                    return
                }
                else { throw }
            }
        }

        if ([string]::IsNullOrEmpty($RootDriveId))
        {
            Write-Error "`$RootDriveId is empty. We couldn't get it with Get-MSGraphGroupRootFolder."
            return
        }
        
        # Get the files and folders in the root drive
        try {
            $CurrentDrive = Get-MSGraphGroupDriveItems -MaxResults $MaxResults -GroupId $GroupId -DriveId $RootDriveId -AccessToken $AccessToken
        }
        catch {
            $msg = $_.Exception.Message
            if ($msg -match 'Access denied' -or $msg -match 'Resource is not found\.') {
                Write-Verbose "Group ${GroupId} drive ${RootDriveId}: $msg (skipping)"
                return
            }
            else { throw }
        }

        # return
        $CurrentDrive

        foreach ($file in $CurrentDrive)
        {
            Write-Verbose "File or folder name : ""$($file.name)"""

            if ($null -eq $file.folder)
            {
                continue
            }
            
            Get-MSGraphGroupDriveItemsContent -MaxResults $MaxResults -GroupId $GroupId -RootDriveId "$($file.id)" -AccessToken $AccessToken
        }
    }
}

# Get the groups drive items content
# Jun 1st 2022
function Get-MSGraphGroupsDriveItemsContent
{
    <#
    .SYNOPSIS
    Get the M365 groups drive items content.

    .DESCRIPTION
    Get recursively the groups drive items content i.e. name, download URL, etc.
    The items returned by Get-MSGraphPersonalDriveItemsContent don't appear.

    .PARAMETER AccessToken
    Access token used to get the groups drive items content. It's resource must be https://graph.microsoft.com.

    .PARAMETER OnlyTeams
    Only query the groups that contains a team i.e. get only the files in these groups. See Get-MSGraphGroupsWithTeam for more informations.
    Some files may not appears so prefer to not use it.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>$data = Get-AADIntMSGraphGroupsDriveItemsContent -AccessToken $AccessToken
    PS C:\>$data.'@microsoft.graph.downloadUrl'

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphGroupsDriveItemsContent -AccessToken $AccessToken -OnlyTeams $True
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $False)]
        [bool]$OnlyTeams = $false,
        [Parameter(Mandatory = $False)]
        [int]$MaxResults = 1000
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894 "

        if ($OnlyTeams)
        {
            $Groups = Get-MSGraphGroupsWithTeam -AccessToken $AccessToken
        }
        else
        {
            $Groups = Get-MSGraphM365Groups -AccessToken $AccessToken
        }

        # return
        $Groups

        foreach ($groupId in $Groups.Id)
        {
            Write-Verbose "Group identifier : ""$groupId"""

            Get-MSGraphGroupDriveItemsContent -MaxResults $MaxResults -GroupId "$groupId" -AccessToken $AccessToken
        }
    }
}

# Get the site root drive
# Sep 4th 2025
function Get-MSGraphSiteRootFolder
{
    <#
    .SYNOPSIS
    Get the root drive (root folder) of a SharePoint site.

    .DESCRIPTION
    Returns the drive/root object for the given site id.

    .PARAMETER SiteId
    The site identifier (siteId or combined host, path ID) accepted by Microsoft Graph.

    .PARAMETER AccessToken
    Access token (resource https://graph.microsoft.com).

    .Example
    PS C:\>$at = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"
    PS C:\>Get-AADIntMSGraphSiteRootFolder -SiteId "contoso.sharepoint.com,1234abcd-0000-1111-2222-ffffffffffff,abcd1234-0000-1111-2222-ffffffffffff" -AccessToken $at
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$SiteId,
        [Parameter(Mandatory=$False)]
        [String]$AccessToken
    )
    Process
    {
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"
        Call-MSGraphAPI -AccessToken $AccessToken -API "sites/$SiteId/drive/root" -ApiVersion "v1.0"
    }
}

# Get site drive items
# Sep 4th 2025
function Get-MSGraphSiteDriveItems
{
    <#
    .SYNOPSIS
    Get drive items (children) for a SharePoint site drive folder.

    .DESCRIPTION
    Lists the direct children for the specified folder (DriveId parameter holds the item id under /drive/items/{id}/children).

    .PARAMETER SiteId
    Site identifier.

    .PARAMETER DriveId
    Item (drive item) identifier whose children to list (use root id from Get-MSGraphSiteRootFolder for top-level).

    .PARAMETER AccessToken
    Access token (Graph).
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)] [String]$SiteId,
        [Parameter(Mandatory=$True)] [String]$DriveId,
        [Parameter(Mandatory=$False)] [String]$AccessToken,
        [Parameter(Mandatory=$False)] [int]$MaxResults=1000
    )
    Process
    {
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"
        Call-MSGraphAPI -MaxResults $MaxResults -AccessToken $AccessToken -API "sites/$SiteId/drive/items/$DriveId/children" -ApiVersion "v1.0"
    }
}

# Get site drive items content (recursive)
# Sep 4th 2025
function Get-MSGraphSiteDriveItemsContent
{
    <#
    .SYNOPSIS
    Recursively enumerate drive items (files/folders) in a SharePoint site.

    .DESCRIPTION
    Similar to Get-MSGraphGroupDriveItemsContent but uses /sites/{siteId}/drive/ endpoints.
    Returns each item as it’s discovered (write-as-you-go). subfolders are traversed depth-first.

    .PARAMETER SiteId
    Site identifier.

    .PARAMETER RootDriveId
    Optional starting drive item id (folder). If omitted, the site root drive/root is used.

    .PARAMETER AccessToken
    Graph access token.

    .PARAMETER MaxResults
    Maximum items per paged collection request (soft cap across pagination loop).
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)] [String]$SiteId,
        [Parameter(Mandatory=$False)] [String]$RootDriveId,
        [Parameter(Mandatory=$False)] [String]$AccessToken,
        [Parameter(Mandatory=$False)] [int]$MaxResults=1000
    )
    Process
    {
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        if ([string]::IsNullOrEmpty($RootDriveId))
        {
            try {
                $root = Get-MSGraphSiteRootFolder -SiteId $SiteId -AccessToken $AccessToken -ErrorAction Stop
                $RootDriveId = $root.id
                $root
            } catch {
                $msg = $_.Exception.Message
                if ($msg -match 'Access denied' -or $msg -match 'Resource is not found\.') {
                    Write-Verbose "Site ${SiteId}: $msg (skipping)"
                    return
                } else { throw }
            }
        }

        if ([string]::IsNullOrEmpty($RootDriveId)) { Write-Error "`$RootDriveId is empty. Could not resolve site root."; return }

        $items = $null
        try {
            $items = Get-MSGraphSiteDriveItems -SiteId $SiteId -DriveId $RootDriveId -AccessToken $AccessToken -MaxResults $MaxResults
        } catch {
            $msg = $_.Exception.Message
            if ($msg -match 'Access denied' -or $msg -match 'Resource is not found\.') {
                Write-Verbose "Site $SiteId drive ${RootDriveId}: $msg (skipping)"
                return
            } else { throw }
        }

        $items

        foreach($item in $items) {
            Write-Verbose "Site $SiteId item: $($item.name)"
            if ($null -eq $item.folder) { continue }
            Get-MSGraphSiteDriveItemsContent -SiteId $SiteId -RootDriveId $item.id -AccessToken $AccessToken -MaxResults $MaxResults
        }
    }
}


# Get the root site items contents
# Sep 4th 2025
function Get-MSGraphRootSiteDriveItemsContent
{

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $False)]
        [int]$MaxResults = 1000
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894 "

        # Get the root site information
        $RootSite = Get-MSGraphRootSite -AccessToken $AccessToken

        Get-MSGraphSiteDriveItemsContent -SiteId $RootSite.id -AccessToken $AccessToken -MaxResults $MaxResults
    }
}

# Sep 4th 2025
function Get-MSGraphPersonalDownloadFiles
{
    <#
    .SYNOPSIS
    Download all files from user's OneDrive.

    .DESCRIPTION
    Download all files from user's OneDrive. This includes files uploaded to Teams chats by the user. 

    .PARAMETER AccessToken
    Access token used to get the personal files.

    .PARAMETER Destination
    Directory where to store the files.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphPersonalDownloadFiles -AccessToken $AccessToken -Destination "C:\Downloads\OneDrivePersonal"
    #>

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $False)]
        [String]$Destination = ".",
        [Parameter(Mandatory = $False)]
        [int]$MaxResults = 1000
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"
        
        Get-MSGraphPersonalDriveItemsContent -AccessToken $AccessToken -MaxResults $MaxResults | DownloadFile -Directory $Destination

        while (Get-BitsTransfer)
        {
            Get-BitsTransfer | ForEach-Object {
                if ($_."JobState" -contains "Transferred")
                {
                    Write-Host "File transferred."
                    Complete-BitsTransfer $_
                }
            }
        }
    }
}

# Sep 4th 2025
function Get-MSGraphGroupsDownloadFiles
{
    <#
    .SYNOPSIS
    Download all files from M365 groups that the user has access to.

    .DESCRIPTION
    Download all files from M365 groups. This includes files uploaded to Teams channels.

    .PARAMETER AccessToken
    Access token used to get the groups files.

    .PARAMETER Destination
    Directory where to store the files.

    .PARAMETER OnlyTeams
    Only query the groups have a team associated with them. See Get-MSGraphGroupsWithTeam for more information.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphGroupsDownloadFiles -AccessToken $AccessToken -Destination "C:\Downloads\Groups"

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphGroupsDownloadFiles -AccessToken $AccessToken -Destination "C:\Downloads\Groups" -OnlyTeams $True
    #>

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $False)]
        [String]$Destination = ".",
        [Parameter(Mandatory = $False)]
        [bool]$OnlyTeams = $false,
        [Parameter(Mandatory = $False)]
        [int]$MaxResults = 1000
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Get-MSGraphGroupsDriveItemsContent -AccessToken $AccessToken -OnlyTeams $OnlyTeams -MaxResults $MaxResults | DownloadFile -Directory $Destination

        while (Get-BitsTransfer)
        {
            Get-BitsTransfer | ForEach-Object {
                if ($_."JobState" -contains "Transferred")
                {
                    Write-Host "File transferred."
                    Complete-BitsTransfer $_
                }
            }
        }
    }
}

# Sep 4th 2025
function Get-MSGraphRootSiteDownloadFiles
{
    <#
    .SYNOPSIS
    Download all files from the root SharePoint site.

    .DESCRIPTION
    Download all files from the root SharePoint site.

    .PARAMETER AccessToken
    Access token used to get the root site files.

    .PARAMETER Destination
    Directory where to store the files.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphRootSiteDownloadFiles -AccessToken $AccessToken -Destination "C:\Downloads\RootSite"

    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $False)]
        [String]$Destination = ".",
        [Parameter(Mandatory = $False)]
        [int]$MaxResults = 1000
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Get-MSGraphRootSiteDriveItemsContent -AccessToken $AccessToken -MaxResults $MaxResults | DownloadFile -Directory $Destination

        while (Get-BitsTransfer)
        {
            Get-BitsTransfer | ForEach-Object {
                if ($_."JobState" -contains "Transferred")
                {
                    Write-Host "File transferred."
                    Complete-BitsTransfer $_
                }
            }
        }
    }
}

# Download all the file items in the current directory
# Jun 30st 2022
# ---------------
# Get-MSGraphFiles
# 	Get-MSGraphGroupsDriveItemsContent
# 		Get-MSGraphGroups - /groups
# 			Get-MSGraphGroupDriveItemsContent - recursive
# 				Get-MSGraphGroupRootFolder - "groups/{group_id}/drive/root"
# 				Get-MSGraphGroupDriveItems - "groups/{group_id}/drive/items/{drive_id}/children"
# 	Get-MSGraphPersonalDriveItemsContent - recursive
# 		Get-MSGraphPersonalRootFolder - "me/drive/root"
# 		Get-MSGraphPersonalDriveItems - "me/drive/items/{drive_id}/children"
function Get-MSGraphFiles
{
    <#
    .SYNOPSIS
    Download all the file items in the current directory.

    .DESCRIPTION
    Download all the file items in the current directory.

    .PARAMETER AccessToken
    Access token used to get the groups drive items content. It's resource must be https://graph.microsoft.com.

    .PARAMETER Destination
    Directory where to store the files.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphFiles -AccessToken $AccessToken

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphFiles -AccessToken $AccessToken -Destination .\Files\
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $False)]
        [String]$Destination = "",
        [Parameter(Mandatory = $False)]
        [int]$MaxResults = 1000
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Get-MSGraphGroupsDriveItemsContent -AccessToken $AccessToken -MaxResults $MaxResults | DownloadFile -Directory $Destination
        Get-MSGraphPersonalDriveItemsContent -AccessToken $AccessToken -MaxResults $MaxResults | DownloadFile -Directory $Destination

        while (Get-BitsTransfer)
        {
            Get-BitsTransfer | ForEach-Object {
                if ($_."JobState" -contains "Transferred")
                {
                    Write-Host "File transferred."
                    Complete-BitsTransfer $_
                }
            }
        }
    }
}

# Gets groups conversations
# Jun 1st 2022
function Get-MSGraphGroupConversations
{
    <#
    .SYNOPSIS
    Get the group conversations.

    .DESCRIPTION
    Get the group conversations.

    .PARAMETER AccessToken
    Access token used to get the group conversations.

    .PARAMETER GroupId
    Group identifier.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphGroupConversations -GroupId "0fdc2543-0516-4b79-a017-a70a54f4d57d" -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [GUID]$GroupId,
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $False)]
        [int]$MaxResults = 1000
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -MaxResults $MaxResults -AccessToken $AccessToken -API "groups/$($GroupId.ToString())/conversations" -ApiVersion v1.0
    }
}

# Gets the drive
# Jun 1st 2022
function Get-MSGraphDrive
{
    <#
    .SYNOPSIS
    Get the drive.

    .DESCRIPTION
    Get the drive.

    .PARAMETER AccessToken
    Access token used to get the drive.

    .PARAMETER DriveId
    Drive identifier.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphDrive -DriveId "b!ht8X4_tjwEyhy9ygVlJ73JhDYmNApj9OjdQiCVmfCG_Olxib4KXkSZnbgUIBKexH" -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$DriveId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "drives/$DriveId" -ApiVersion v1.0
    }
}

# Gets the current user joined teams
# Jun 1st 2022
function Get-MSGraphPersonalJoinedTeams
{
    <#
    .SYNOPSIS
    Get the current user joined teams.

    .DESCRIPTION
    Get the current user joined teams. It returns (403) Forbidden for unprivileged user.
    See https://docs.microsoft.com/fr-fr/graph/api/user-list-joinedteams?view=graph-rest-1.0&tabs=http.

    .PARAMETER AccessToken
    Access token used to get the current user joined teams.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphPersonalJoinedTeams -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "me/joinedTeams" -ApiVersion v1.0
    }
}

# Gets the user joined teams
# Jun 1st 2022
function Get-MSGraphJoinedTeams
{
    <#
    .SYNOPSIS
    Get the user joined teams.

    .DESCRIPTION
    Get the user joined teams. It returns (403) Forbidden for unprivileged user.
    See https://docs.microsoft.com/fr-fr/graph/api/user-list-joinedteams?view=graph-rest-1.0&tabs=http.

    .PARAMETER AccessToken
    Access token used to get the user joined teams.

    .PARAMETER UserId
    User identifier or principal name

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphJoinedTeams -AccessToken $AccessToken -UserId 20c45127-c075-4b6d-95dc-c3095d53e6bb
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$UserId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserId/joinedTeams" -ApiVersion v1.0
    }
}

# Gets the current user relations
# Jun 28 2022
function Get-MSGraphPersonalPeople
{
    <#
    .SYNOPSIS
    Get the current user relations.

    .DESCRIPTION
    Get the current user relations.
    See https://docs.microsoft.com/en-us/graph/api/user-list-people?view=graph-rest-1.0&tabs=http and https://docs.microsoft.com/en-us/graph/people-example.

    .PARAMETER AccessToken
    Access token used to get the current user relations.

    .PARAMETER ApiVersion
    Optional. Set to v1.0 by default.

    .PARAMETER ResultsCount
    Optional. Set to 20 by default.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphPersonalPeople -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $False)]
        [String]$ApiVersion = "v1.0",
        [Parameter(Mandatory = $False)]
        [int]$ResultsCount = 20
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "me/people/" -ApiVersion $ApiVersion -QueryString "`$top=$ResultsCount"
    }
}

# Gets the user relations
# Jun 28 2022
function Get-MSGraphPeople
{
    <#
    .SYNOPSIS
    Get the user relations.

    .DESCRIPTION
    Get the user relations.
    See https://docs.microsoft.com/en-us/graph/api/user-list-people?view=graph-rest-1.0&tabs=http and https://docs.microsoft.com/en-us/graph/people-example.

    .PARAMETER AccessToken
    Access token used to get the user relations.

    .PARAMETER ApiVersion
    Optional. Set to v1.0 by default.

    .PARAMETER ResultsCount
    Optional. Set to 20 by default.

    .PARAMETER UserId
    User identifier or principal name

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphPeople -AccessToken $AccessToken -UserId 64d999db-fc15-459c-bccf-5fa5908557aa
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $False)]
        [String]$ApiVersion = "v1.0",
        [Parameter(Mandatory = $False)]
        [int]$ResultsCount = 20,
        [Parameter(Mandatory = $True)]
        [String]$UserId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserId/people/" -ApiVersion $ApiVersion -QueryString "`$top=$ResultsCount"
    }
}

# Gets the documents shared with the current user
# Jun 28 2022
function Get-MSGraphPersonalShared
{
    <#
    .SYNOPSIS
    Get the documents shared with the current user.

    .DESCRIPTION
    Get the documents shared with the current user.
    See https://docs.microsoft.com/en-us/graph/api/insights-list-shared?view=graph-rest-1.0.

    .PARAMETER AccessToken
    Access token used to get the documents shared with the current user.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphPersonalShared -AccessToken $AccessToken | Format-List
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "me/insights/shared" -ApiVersion "v1.0"
    }
}

# Gets the documents shared with the user
# Jun 28 2022
function Get-MSGraphShared
{
    <#
    .SYNOPSIS
    Get the documents shared with the user.

    .DESCRIPTION
    Get the documents shared with the user.
    See https://docs.microsoft.com/en-us/graph/api/insights-list-shared?view=graph-rest-1.0.
    For now only the user can make requests using the user's id or principal name i.e. (403) Forbidden for any other UserId.

    .PARAMETER AccessToken
    Access token used to get the documents shared with the user.

    .PARAMETER UserId
    User identifier or principal name

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphShared -AccessToken $AccessToken -UserId 64d999db-fc15-459c-bccf-5fa5908557aa | Format-List
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$UserId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserId/insights/shared" -ApiVersion "v1.0"
    }
}

# Gets the shared resource
# Jun 28 2022
function Get-MSGraphSharedResource
{
    <#
    .SYNOPSIS
    Get the shared resource.

    .DESCRIPTION
    Get the shared resource (driveItem for instance).
    See https://docs.microsoft.com/en-us/graph/api/insights-list-shared?view=graph-rest-1.0.

    .PARAMETER AccessToken
    Access token used to get the shared resource.

    .PARAMETER SharedInsightId
    Shared insight identifier

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphSharedResource -AccessToken $AccessToken -SharedInsightId AVfrRLDbFMdEmde8XJFEHxSMo4xxto32SIRjCyala73V_uBfxpe2V06M7gEopuP3Ewo_qT9gdn1Jm1_4ZYvWF49X60Sw2xTHRJnXvFyRRB8UBA
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$SharedInsightId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "me/insights/shared/$SharedInsightId/resource" -ApiVersion "v1.0"
    }
}

# Gets the current user trending documents
# Jul 22 2022
function Get-MSGraphPersonalTrending
{
    <#
    .SYNOPSIS
    Get the current user trending documents.

    .DESCRIPTION
    Get the current user trending documents.

    .PARAMETER AccessToken
    Access token used to get the current user trending documents.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphPersonalTrending -AccessToken $AccessToken | Format-List
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "me/insights/trending" -ApiVersion "v1.0"
    }
}

# Gets the user trending documents
# Jul 22nd 2022
function Get-MSGraphTrending
{
    <#
    .SYNOPSIS
    Get the user trending documents.

    .DESCRIPTION
    Get the user trending documents.

    .PARAMETER AccessToken
    Access token used to get the user trending documents.

    .PARAMETER UserId
    User identifier or principal name

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphTrending -AccessToken $AccessToken -UserId 64d999db-fc15-459c-bccf-5fa5908557aa | Format-List
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$UserId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserId/insights/trending" -ApiVersion "v1.0"
    }
}

# Gets the current user used documents
# Jul 22 2022
function Get-MSGraphPersonalUsed
{
    <#
    .SYNOPSIS
    Get the current user used documents.

    .DESCRIPTION
    Get the current user used documents.

    .PARAMETER AccessToken
    Access token used to get the current user used documents.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphPersonalUsed -AccessToken $AccessToken | Format-List
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "me/insights/used" -ApiVersion "v1.0"
    }
}

# Gets the used resource
# Jun 28 2022
function Get-MSGraphUsedResource
{
    <#
    .SYNOPSIS
    Get the used resource.

    .DESCRIPTION
    Get the used resource (driveItem for instance).

    .PARAMETER AccessToken
    Access token used to get the used resource.

    .PARAMETER UsedInsightId
    Used insight identifier

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphUsedResource -AccessToken $AccessToken -UsedInsightId AVfrRLDbFMdEmde8XJFEHxSMo4xxto32SIRjCyala73V_uBfxpe2V06M7gEopuP3Ewo_qT9gdn1Jm1_4ZYvWF49X60Sw2xTHRJnXvFyRRB8UBA
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$UsedInsightId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "me/insights/used/$UsedInsightId/resource" -ApiVersion "v1.0"
    }
}

# Gets the user used documents
# Jul 22nd 2022
function Get-MSGraphUsed
{
    <#
    .SYNOPSIS
    Get the user used documents.

    .DESCRIPTION
    Get the user used documents.

    .PARAMETER AccessToken
    Access token used to get the user used documents.

    .PARAMETER UserId
    User identifier or principal name

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphUsed -AccessToken $AccessToken -UserId 64d999db-fc15-459c-bccf-5fa5908557aa | Format-List
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$UserId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserId/insights/used" -ApiVersion "v1.0"
    }
}

# Gets current user registered devices
# Jun 28 2022
function Get-MSGraphPersonalRegisteredDevices
{
    <#
    .SYNOPSIS
    Get current user registered devices.

    .DESCRIPTION
    Get current user registered devices.
    See https://docs.microsoft.com/en-us/graph/api/user-list-registereddevices?view=graph-rest-1.0&tabs=http.
    Can return nothing.

    .PARAMETER AccessToken
    Access token used to get current user registered devices.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphPersonalRegisteredDevices -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "me/registeredDevices" -ApiVersion "v1.0"
    }
}

# Gets the user registered devices
# Jun 28 2022
function Get-MSGraphRegisteredDevices
{
    <#
    .SYNOPSIS
    Get the user registered devices.

    .DESCRIPTION
    Get the user registered devices.
    See https://docs.microsoft.com/en-us/graph/api/user-list-registereddevices?view=graph-rest-1.0&tabs=http.
    For now only the user can make requests using the user's id or principal name i.e. (403) Forbidden for any other UserId.
    Can return nothing.

    .PARAMETER AccessToken
    Access token used to get the user registered devices.

    .PARAMETER UserId
    User identifier or principal name

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphRegisteredDevices -AccessToken $AccessToken -UserId 64d999db-fc15-459c-bccf-5fa5908557aa
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$UserId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserId/registeredDevices" -ApiVersion "v1.0"
    }
}

# Gets current user scope-role membership
# Jun 28 2022
function Get-MSGraphPersonalScopeRoleMembership
{
    <#
    .SYNOPSIS
    Get current user scope-role membership.

    .DESCRIPTION
    Get current user scope-role membership.
    See https://docs.microsoft.com/en-us/graph/api/user-list-scopedrolememberof?view=graph-rest-beta&tabs=http.
    Can return nothing.

    .PARAMETER AccessToken
    Access token used to get current user scope-role membership.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphPersonalScopeRoleMembership -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "me/scopedRoleMemberOf" -ApiVersion "beta"
    }
}

# Gets the user scope-role membership
# Jun 28 2022
function Get-MSGraphScopeRoleMembership
{
    <#
    .SYNOPSIS
    Get the user scope-role membership.

    .DESCRIPTION
    Get the user scope-role membership.
    See https://docs.microsoft.com/en-us/graph/api/user-list-scopedrolememberof?view=graph-rest-beta&tabs=http.
    Can return nothing.

    .PARAMETER AccessToken
    Access token used to get the user scope-role membership.

    .PARAMETER UserId
    User identifier or principal name

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphScopeRoleMembership -AccessToken $AccessToken -UserId 64d999db-fc15-459c-bccf-5fa5908557aa
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$UserId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserId/scopedRoleMemberOf" -ApiVersion "beta"
    }
}

# Gets the groups, directory roles, and administrative units that the current user is a direct member of
# Jun 28 2022
function Get-MSGraphPersonalMemberOf
{
    <#
    .SYNOPSIS
    Get the groups, directory roles, and administrative units that the current user is a direct member of.

    .DESCRIPTION
    Get the groups, directory roles, and administrative units that the current user is a direct member of.
    See https://docs.microsoft.com/en-us/graph/api/user-list-memberof?view=graph-rest-1.0&tabs=http.

    .PARAMETER AccessToken
    Access token used to get the groups, directory roles, and administrative units that the current user is a direct member of.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphPersonalMemberOf -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "me/memberOf" -ApiVersion "v1.0"
    }
}

# Gets the groups, directory roles, and administrative units that the current user is a direct member of
# Jun 28 2022
function Get-MSGraphUserMemberOf
{
    <#
    .SYNOPSIS
    Get the groups, directory roles, and administrative units that the current user is a direct member of.

    .DESCRIPTION
    Get the groups, directory roles, and administrative units that the current user is a direct member of.
    See https://docs.microsoft.com/en-us/graph/api/user-list-memberof?view=graph-rest-1.0&tabs=http.

    # Url encode for external users, replace # with %23
    # $UserPrincipalName = $UserPrincipalName.Replace("#", "%23")

    .PARAMETER AccessToken
    Access token used to get the groups, directory roles, and administrative units that the user is a direct member of.

    .PARAMETER UserId
    User identifier or principal name

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphUserMemberOf -AccessToken $AccessToken -UserId 64d999db-fc15-459c-bccf-5fa5908557aa
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$UserId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserId/memberOf" -ApiVersion "v1.0"
    }
}

# Gets the groups, directory roles, and administrative units that the current user is a member of. Also return all groups the user is a nested member of.
# Jun 28 2022
function Get-MSGraphUserTransitiveMemberOf
{
    <#
    .SYNOPSIS
    Get the groups, directory roles, and administrative units that the current user is a member of.
    Also return all groups the user is a nested member of.

    .DESCRIPTION
    Get the groups, directory roles, and administrative units that the current user is a member of.
    Also return all groups the user is a nested member of.
    See https://docs.microsoft.com/en-us/graph/api/user-list-transitivememberof?view=graph-rest-beta&tabs=http.

    .PARAMETER AccessToken
    Access token used to get the groups, directory roles, and administrative units that the user is a member of.

    .PARAMETER UserId
    User identifier or principal name

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphUserTransitiveMemberOf -AccessToken $AccessToken -UserId 64d999db-fc15-459c-bccf-5fa5908557aa
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$UserId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserId/transitiveMemberOf" -ApiVersion "v1.0"
    }
}

# Get the tenant applications
# Jul 16 2022
function Get-MSGraphApplications
{
    <#
    .SYNOPSIS
    Get the tenant applications.

    .DESCRIPTION
    Get the tenant applications.
    See https://docs.microsoft.com/en-us/graph/api/application-list?view=graph-rest-1.0&tabs=http.
    The Microsoft applications are not returned. See AccessToken_utils.ps1 to identify them or
    https://github.com/MicrosoftDocs/SupportArticles-docs/blob/main/support/azure/active-directory/verify-first-party-apps-sign-in.md#application-ids-for-commonly-used-microsoft-applications=.

    .PARAMETER AccessToken
    Access token used to get the tenant applications

    .PARAMETER QueryString
    Optional. OData query string to filter, sort, and select the properties for the applications.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphApplications -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $False)]
        [String]$QueryString
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "applications" -ApiVersion "v1.0" -QueryString $QueryString
    }
}

# Get the tenant application
# Jul 16 2022
function Get-MSGraphApplication
{
    <#
    .SYNOPSIS
    Get the tenant application.

    .DESCRIPTION
    Get the tenant application.
    See https://docs.microsoft.com/en-us/graph/api/application-get?view=graph-rest-1.0&tabs=http.

    .PARAMETER AccessToken
    Access token used to get the tenant application

    .PARAMETER AppObjectId
    Application identifier

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphApplication -AccessToken $AccessToken -AppObjectId ""
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$AppObjectId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "applications/$AppObjectId" -ApiVersion "v1.0"
    }
}

# Get the tenant application token issuance policies
# Jul 22 2022
function Get-MSGraphApplicationTokenIssuancePolicies
{
    <#
    .SYNOPSIS
    Get the tenant application token issuance policies.

    .DESCRIPTION
    Get the tenant application token issuance policies.

    .PARAMETER AccessToken
    Access token used to get the tenant application token issuance policies

    .PARAMETER AppObjectId
    Application identifier

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphApplicationTokenIssuancePolicies -AccessToken $AccessToken -AppObjectId ""
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$AppObjectId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "applications/$AppObjectId/tokenIssuancePolicies" -ApiVersion "v1.0"
    }
}

# Get the tenant application token lifetime policies
# Jul 22 2022
function Get-MSGraphApplicationTokenLifetimePolicies
{
    <#
    .SYNOPSIS
    Get the tenant application token lifetime policies.

    .DESCRIPTION
    Get the tenant application token lifetime policies.

    .PARAMETER AccessToken
    Access token used to get the tenant application token lifetime policies

    .PARAMETER AppObjectId
    Application identifier

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphApplicationTokenLifetimePolicies -AccessToken $AccessToken -AppObjectId ""
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$AppObjectId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "applications/$AppObjectId/tokenLifetimePolicies" -ApiVersion "v1.0"
    }
}

# Get the tenant application owners
# Jul 16 2022
function Get-MSGraphApplicationOwners
{
    <#
    .SYNOPSIS
    Get the tenant application owners.

    .DESCRIPTION
    Get the tenant application owners.
    See https://docs.microsoft.com/en-us/graph/api/application-list-owners?view=graph-rest-1.0&tabs=http.

    .PARAMETER AccessToken
    Access token used to get the tenant application owners

    .PARAMETER AppObjectId
    Application identifier

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphApplicationOwners -AccessToken $AccessToken -AppObjectId ""
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$AppObjectId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "applications/$AppObjectId/owners" -ApiVersion "v1.0"
    }
}

# Get the deleted groups
# Jul 16 2022
function Get-MSGraphDeletedGroups
{
    <#
    .SYNOPSIS
    Get the deleted groups.

    .DESCRIPTION
    Get the deleted groups.
    See https://docs.microsoft.com/en-us/graph/api/directory-deleteditems-list?view=graph-rest-1.0&tabs=http.

    .PARAMETER AccessToken
    Access token used to get the deleted groups

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphDeletedGroups -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "directory/deletedItems/microsoft.graph.group" -ApiVersion "v1.0"
    }
}

# Get the deleted applications
# Jul 16 2022
function Get-MSGraphDeletedApplications
{
    <#
    .SYNOPSIS
    Get the deleted applications.

    .DESCRIPTION
    Get the deleted applications.
    See https://docs.microsoft.com/en-us/graph/api/directory-deleteditems-list?view=graph-rest-1.0&tabs=http.

    .PARAMETER AccessToken
    Access token used to get the deleted applications

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphDeletedApplications -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "directory/deletedItems/microsoft.graph.application" -ApiVersion "v1.0"
    }
}

# Get the deleted service principals
# Jul 16 2022
function Get-MSGraphDeletedServicePrincipals
{
    <#
    .SYNOPSIS
    Get the deleted service principals.

    .DESCRIPTION
    Get the deleted service principals.
    See https://docs.microsoft.com/en-us/graph/api/directory-deleteditems-list?view=graph-rest-1.0&tabs=http.

    .PARAMETER AccessToken
    Access token used to get the deleted service principals

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphDeletedServicePrincipals -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "directory/deletedItems/microsoft.graph.servicePrincipal" -ApiVersion "v1.0"
    }
}

# Get the deleted users
# Jul 16 2022
function Get-MSGraphDeletedUsers
{
    <#
    .SYNOPSIS
    Get the deleted users.

    .DESCRIPTION
    Get the deleted users.
    See https://docs.microsoft.com/en-us/graph/api/directory-deleteditems-list?view=graph-rest-1.0&tabs=http.

    .PARAMETER AccessToken
    Access token used to get the deleted users

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphDeletedUsers -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "directory/deletedItems/microsoft.graph.user" -ApiVersion "v1.0"
    }
}

# Get the deleted devices
# Jul 16 2022
function Get-MSGraphDeletedDevices
{
    <#
    .SYNOPSIS
    Get the deleted devices.

    .DESCRIPTION
    Get the deleted devices.
    See https://docs.microsoft.com/en-us/graph/api/directory-deleteditems-list?view=graph-rest-1.0&tabs=http.

    .PARAMETER AccessToken
    Access token used to get the deleted devices

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphDeletedDevices -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "directory/deletedItems/microsoft.graph.device" -ApiVersion "v1.0"
    }
}

# Get the deleted item
# Jul 16 2022
function Get-MSGraphDeletedItem
{
    <#
    .SYNOPSIS
    Get the deleted item.

    .DESCRIPTION
    Get the deleted item.
    See https://docs.microsoft.com/en-us/graph/api/directory-deleteditems-get?view=graph-rest-1.0&tabs=http.

    .PARAMETER AccessToken
    Access token used to get the deleted item

    .PARAMETER DeletedItemId
    Deleted item identifier

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphDeletedItem -AccessToken $AccessToken -DeletedItemId ""
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$DeletedItemId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "directory/deletedItems/$DeletedItemId" -ApiVersion "v1.0"
    }
}

# Gets the identity providers
# Jul 21th 2022
function Get-MSGraphIdentityProviders
{
    <#
    .SYNOPSIS
    Returns the identity providers

    .DESCRIPTION
    Returns the identity providers

    .PARAMETER AccessToken
    Access token used to get the identity providers

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphIdentityProviders -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "identity/identityProviders" -ApiVersion v1.0 
    }
}

# Gets the identity provider
# Jul 21th 2022
function Get-MSGraphIdentityProvider
{
    <#
    .SYNOPSIS
    Returns the identity provider

    .DESCRIPTION
    Returns the identity provider

    .PARAMETER AccessToken
    Access token used to get the identity provider

    .PARAMETER IdentityProviderId
    IdentityProvider identifier

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphIdentityProvider -AccessToken $AccessToken -IdentityProviderId "Amazon-OAUTH"
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$IdentityProviderId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "identity/identityProviders/$IdentityProviderId" -ApiVersion v1.0 
    }
}


# Gets the identity providers supported in a directory.
# Jul 21th 2022
function Get-MSGraphAvailableProviderTypes
{
    <#
    .SYNOPSIS
    Returns the identity providers supported in a directory.

    .DESCRIPTION
    Returns the identity providers supported in a directory.

    .PARAMETER AccessToken
    Access token used to get the identity providers supported in a directory.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphAvailableProviderTypes -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "identity/identityProviders/availableProviderTypes" -ApiVersion v1.0 
    }
}

# Gets the samlOrWsFedExternalDomainFederation
# Jul 21th 2022
function Get-MSGraphSamlOrWsFedExternalDomainFederation
{
    <#
    .SYNOPSIS
    Returns the samlOrWsFedExternalDomainFederation

    .DESCRIPTION
    Returns the samlOrWsFedExternalDomainFederation

    .PARAMETER AccessToken
    Access token used to get the samlOrWsFedExternalDomainFederation

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphSamlOrWsFedExternalDomainFederation -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "directory/federationConfigurations/graph.samlOrWsFedExternalDomainFederation" -ApiVersion v1.0 
    }
}

# Gets the list of all externalDomainName objects for a samlOrWsFedExternalDomainFederation.
# Jul 21th 2022
function Get-MSGraphSamlOrWsFedExternalDomainFederationDomains
{
    <#
    .SYNOPSIS
    Returns the list of all externalDomainName objects for a samlOrWsFedExternalDomainFederation.

    .DESCRIPTION
    Returns the list of all externalDomainName objects for a samlOrWsFedExternalDomainFederation.

    .PARAMETER AccessToken
    Access token used to get the list of all externalDomainName objects for a samlOrWsFedExternalDomainFederation.

    .PARAMETER SamlOrWsFedExternalDomainFederationId
    SamlOrWsFedExternalDomainFederation identifier

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphSamlOrWsFedExternalDomainFederationDomains -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$SamlOrWsFedExternalDomainFederationId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "directory/federationConfigurations/graph.samlOrWsFedExternalDomainFederation/$SamlOrWsFedExternalDomainFederationId/domains" -ApiVersion v1.0 
    }
}

# Gets the risky users
# Jul 21th 2022
function Get-MSGraphRiskyUsers
{
    <#
    .SYNOPSIS
    Returns the risky users

    .DESCRIPTION
    Returns the risky users

    .PARAMETER AccessToken
    Access token used to get the risky users

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphRiskyUsers -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "identityProtection/riskyUsers" -ApiVersion v1.0 
    }
}

# Gets the risky users history
# Jul 21th 2022
function Get-MSGraphRiskyUsersHistory
{
    <#
    .SYNOPSIS
    Returns the risky users history

    .DESCRIPTION
    Returns the risky users history

    .PARAMETER AccessToken
    Access token used to get the risky users history

    .PARAMETER UserId
    UserId identifier

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphRiskyUsersHistory -AccessToken $AccessToken -UserId 39429de5-4135-4ec3-ac2b-884f79b7ad5d
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$UserId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "identityProtection/riskyUsers/$UserId/history" -ApiVersion v1.0 
    }
}

# Gets the risk Detections
# Jul 21th 2022
function Get-MSGraphRiskDetections
{
    <#
    .SYNOPSIS
    Returns the risk Detections

    .DESCRIPTION
    Returns the risk Detections

    .PARAMETER AccessToken
    Access token used to get the risk Detections

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphRiskDetections -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "identityProtection/riskDetections" -ApiVersion v1.0 
    }
}

# Gets the delegated permission grants
# Jul 21th 2022
function Get-MSGraphDelegatedPermissionGrants
{
    <#
    .SYNOPSIS
    Returns the delegated permission grants

    .DESCRIPTION
    Returns the delegated permissions which have been granted for client applications to access APIs on behalf of signed-in users.

    .PARAMETER AccessToken
    Access token used to get the delegated permission grants

    .PARAMETER QueryString
    OData query string to filter the results

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphDelegatedPermissionGrants -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $False)]
        [String]$QueryString
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "oauth2PermissionGrants" -ApiVersion v1.0 -QueryString $QueryString
    }
}

# Gets the delegated permission grants
# Jul 21th 2022
function Get-MSGraphDelegatedPermissionGrant
{
    <#
    .SYNOPSIS
    Returns the delegated permission grant

    .DESCRIPTION
    Returns the delegated permission which have been granted for client applications to access APIs on behalf of signed-in users.
    We find the scope of the user's access tokens so it may be useful to detect malicious device codes which have been granted access by an user.

    .PARAMETER AccessToken
    Access token used to get the delegated permission grant

    .PARAMETER DelegatedPermissionGrantId
    Delegated permission grant identifier

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphDelegatedPermissionGrant -AccessToken $AccessToken -DelegatedPermissionGrantId G4W3inJmmUmy7tLK9GtMj0DOFjDrusFJnBlv_REbveXbmdlkFfycRbzPX6WQhVeq

    clientId    : 8ab7851b-6672-4999-b2ee-d2caf46b4c8f
    consentType : AllPrincipals
    id          : G4W3inJmmUmy7tLK9GtMj0DOFjDrusFJnBlv_REbveU
    principalId : 
    resourceId  : 3016ce40-baeb-49c1-9c19-6ffd111bbde5 
    scope       : openid profile User.Read offline_access   
    
    clientId    : 8ab7851b-6672-4999-b2ee-d2caf46b4c8f
    consentType : Principal
    id          : G4W3inJmmUmy7tLK9GtMj0DOFjDrusFJnBlv_REbveXbmdlkFfycRbzPX6WQhVeq
    principalId : 64d999db-fc15-459c-bccf-5fa5908557aa
    resourceId  : 3016ce40-baeb-49c1-9c19-6ffd111bbde5
    scope       : Mail.Read openid profile offline_access Team.ReadBasic.All Channel.ReadBasic.All ChannelMessage.Read.All Chat.Read Chat.ReadBasic Chat.ReadWrite
                  Contacts.Read Contacts.ReadWrite People.Read.All Calendars.ReadWrite ChannelSettings.Read.All ChannelSettings.ReadWrite.All Directory.Read.All 
                  Directory.ReadWrite.All Group.Read.All Group.ReadWrite.All DeviceManagementApps.ReadWrite.All Files.Read Presence.Read ExternalItem.Read.All Files.Read.All 
                  Sites.Read.All Files.ReadWrite Files.ReadWrite.All Sites.ReadWrite.All AuditLog.Read.All                         
                  
    clientId    : ed7a436e-5d58-4bcc-a13f-d74a5ac34341
    consentType : Principal
    id          : bkN67VhdzEuhP9dKWsNDQUDOFjDrusFJnBlv_REbveXbmdlkFfycRbzPX6WQhVeq
    principalId : 64d999db-fc15-459c-bccf-5fa5908557aa
    resourceId  : 3016ce40-baeb-49c1-9c19-6ffd111bbde5
    scope       : User.Read.All Group.ReadWrite.All openid profile offline_access
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$DelegatedPermissionGrantId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "oauth2PermissionGrants/$DelegatedPermissionGrantId" -ApiVersion v1.0 
    }
}

# Gets the service principals
# Jul 21th 2022
function Get-MSGraphServicePrincipals
{
    <#
    .SYNOPSIS
    Returns the service principals

    .DESCRIPTION
    Returns the service principals

    .PARAMETER AccessToken
    Access token used to get the service principals

    .PARAMETER QueryString
    OData query to apply to the request

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphServicePrincipals -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $False)]
        [String]$QueryString = ""
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "servicePrincipals" -ApiVersion v1.0 -QueryString $QueryString
    }
}

# Gets the service principal
# Jul 21th 2022
function Get-MSGraphServicePrincipal
{
    <#
    .SYNOPSIS
    Returns the service principal

    .DESCRIPTION
    Returns the service principal

    .PARAMETER AccessToken
    Access token used to get the service principal

    .PARAMETER ServicePrincipalId
    Service principal identifier

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphServicePrincipal -AccessToken $AccessToken -ServicePrincipalId 8ab7851b-6672-4999-b2ee-d2caf46b4c8f
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$ServicePrincipalId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "servicePrincipals/$ServicePrincipalId" -ApiVersion v1.0 
    }
}

# Gets the service principal created objects
# Jul 21th 2022
function Get-MSGraphServicePrincipalCreatedObjects
{
    <#
    .SYNOPSIS
    Returns the service principal created objects

    .DESCRIPTION
    Returns the service principal created objects

    .PARAMETER AccessToken
    Access token used to get the service principal created objects

    .PARAMETER ServicePrincipalId
    Service principal identifier

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphServicePrincipalCreatedObjects -AccessToken $AccessToken -ServicePrincipalId 8ab7851b-6672-4999-b2ee-d2caf46b4c8f
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$ServicePrincipalId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "servicePrincipals/$ServicePrincipalId/createdObjects" -ApiVersion v1.0 
    }
}

# Gets the service principal owned objects
# Jul 21th 2022
function Get-MSGraphServicePrincipalOwnedObjects
{
    <#
    .SYNOPSIS
    Returns the service principal owned objects

    .DESCRIPTION
    Returns the service principal owned objects

    .PARAMETER AccessToken
    Access token used to get the service principal owned objects

    .PARAMETER ServicePrincipalId
    Service principal identifier

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphServicePrincipalOwnedObjects -AccessToken $AccessToken -ServicePrincipalId 8ab7851b-6672-4999-b2ee-d2caf46b4c8f
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$ServicePrincipalId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "servicePrincipals/$ServicePrincipalId/ownedObjects" -ApiVersion v1.0 
    }
}

# Gets the service principal app role assignments
# Jul 21th 2022
function Get-MSGraphServicePrincipalAppRoleAssignments
{
    <#
    .SYNOPSIS
    Returns the service principal app role assignments

    .DESCRIPTION
    Returns the service principal app role assignments

    .PARAMETER AccessToken
    Access token used to get the service principal app role assignments

    .PARAMETER ServicePrincipalId
    Service principal identifier

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphServicePrincipalAppRoleAssignments -AccessToken $AccessToken -ServicePrincipalId 8ab7851b-6672-4999-b2ee-d2caf46b4c8f
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$ServicePrincipalId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "servicePrincipals/$ServicePrincipalId/appRoleAssignments" -ApiVersion v1.0 
    }
}

# Gets the service principal app role assigned to
# Jul 21th 2022
function Get-MSGraphServicePrincipalAppRoleAssignedTo
{
    <#
    .SYNOPSIS
    Returns the service principal app role assigned to

    .DESCRIPTION
    Returns the service principal app role assigned to

    .PARAMETER AccessToken
    Access token used to get the service principal app role assigned to

    .PARAMETER ServicePrincipalId
    Service principal identifier

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphServicePrincipalAppRoleAssignedTo -AccessToken $AccessToken -ServicePrincipalId 8ab7851b-6672-4999-b2ee-d2caf46b4c8f
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$ServicePrincipalId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "servicePrincipals/$ServicePrincipalId/appRoleAssignedTo" -ApiVersion v1.0 
    }
}

# Gets the service principal delegated permission classifications
# Jul 21th 2022
function Get-MSGraphServicePrincipalDelegatedPermissionClassifications
{
    <#
    .SYNOPSIS
    Returns the service principal delegated permission classifications

    .DESCRIPTION
    Returns the service principal delegated permission classifications

    .PARAMETER AccessToken
    Access token used to get the service principal delegated permission classifications

    .PARAMETER ServicePrincipalId
    Service principal identifier

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphServicePrincipalDelegatedPermissionClassifications -AccessToken $AccessToken -ServicePrincipalId 8ab7851b-6672-4999-b2ee-d2caf46b4c8f
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$ServicePrincipalId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "servicePrincipals/$ServicePrincipalId/delegatedPermissionClassifications" -ApiVersion v1.0 
    }
}

# Gets the service principal permission grants
# Jul 21th 2022
function Get-MSGraphServicePrincipalPermissionGrants
{
    <#
    .SYNOPSIS
    Returns the service principal permission grants

    .DESCRIPTION
    Returns the service principal permission grants

    .PARAMETER AccessToken
    Access token used to get the service principal permission grants

    .PARAMETER ServicePrincipalId
    Service principal identifier

    .PARAMETER QueryString
    OData query to apply to the request

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphServicePrincipalPermissionGrants -AccessToken $AccessToken -ServicePrincipalId 8ab7851b-6672-4999-b2ee-d2caf46b4c8f
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$ServicePrincipalId,
        [Parameter(Mandatory = $False)]
        [String]$QueryString
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "servicePrincipals/$ServicePrincipalId/oauth2PermissionGrants" -ApiVersion v1.0 -QueryString $QueryString
    }
}

# Gets the service principal membership
# Jul 21th 2022
function Get-MSGraphServicePrincipalMemberOf
{
    <#
    .SYNOPSIS
    Returns the service principal membership

    .DESCRIPTION
    Returns the service principal membership

    .PARAMETER AccessToken
    Access token used to get the service principal membership

    .PARAMETER ServicePrincipalId
    Service principal identifier

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphServicePrincipalMemberOf -AccessToken $AccessToken -ServicePrincipalId 8ab7851b-6672-4999-b2ee-d2caf46b4c8f
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$ServicePrincipalId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "servicePrincipals/$ServicePrincipalId/memberOf" -ApiVersion v1.0 
    }
}

# Gets the service principal membership
# Jul 21th 2022
function Get-MSGraphServicePrincipalTransitiveMemberOf
{
    <#
    .SYNOPSIS
    Returns the service principal membership

    .DESCRIPTION
    Returns the service principal membership

    .PARAMETER AccessToken
    Access token used to get the service principal membership

    .PARAMETER ServicePrincipalId
    Service principal identifier

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphServicePrincipalTransitiveMemberOf -AccessToken $AccessToken -ServicePrincipalId 8ab7851b-6672-4999-b2ee-d2caf46b4c8f
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$ServicePrincipalId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "servicePrincipals/$ServicePrincipalId/transitiveMemberOf" -ApiVersion v1.0 
    }
}

# Gets the service principal owners
# Jul 21th 2022
function Get-MSGraphServicePrincipalOwners
{
    <#
    .SYNOPSIS
    Returns the service principal owners

    .DESCRIPTION
    Returns the service principal owners

    .PARAMETER AccessToken
    Access token used to get the service principal owners

    .PARAMETER ServicePrincipalId
    Service principal identifier

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphServicePrincipalOwners -AccessToken $AccessToken -ServicePrincipalId 8ab7851b-6672-4999-b2ee-d2caf46b4c8f
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$ServicePrincipalId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "servicePrincipals/$ServicePrincipalId/owners" -ApiVersion v1.0 
    }
}

# Gets the service principal claims mapping policies
# Jul 21th 2022
function Get-MSGraphServicePrincipalClaimsMappingPolicies
{
    <#
    .SYNOPSIS
    Returns the service principal claims mapping policies

    .DESCRIPTION
    Returns the service principal claims mapping policies

    .PARAMETER AccessToken
    Access token used to get the service principal claims mapping policies

    .PARAMETER ServicePrincipalId
    Service principal identifier

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphServicePrincipalClaimsMappingPolicies -AccessToken $AccessToken -ServicePrincipalId 8ab7851b-6672-4999-b2ee-d2caf46b4c8f
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$ServicePrincipalId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "servicePrincipals/$ServicePrincipalId/claimsMappingPolicies" -ApiVersion v1.0 
    }
}

# Gets the service principal home realm discovery policies
# Jul 21th 2022
function Get-MSGraphServicePrincipalHomeRealmDiscoveryPolicies
{
    <#
    .SYNOPSIS
    Returns the service principal home realm discovery policies

    .DESCRIPTION
    Returns the service principal home realm discovery policies

    .PARAMETER AccessToken
    Access token used to get the service principal home realm discovery policies

    .PARAMETER ServicePrincipalId
    Service principal identifier

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphServicePrincipalHomeRealmDiscoveryPolicies -AccessToken $AccessToken -ServicePrincipalId 8ab7851b-6672-4999-b2ee-d2caf46b4c8f
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$ServicePrincipalId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "servicePrincipals/$ServicePrincipalId/homeRealmDiscoveryPolicies" -ApiVersion v1.0 
    }
}

# Gets the conditional access policies
# Jul 22nd 2022
function Get-MSGraphConditionalAccessPolicies
{
    <#
    .SYNOPSIS
    Gets tenant's conditional access policies.

    .DESCRIPTION
    Gets tenant's conditional access policies.

    .PARAMETER AccessToken
    Access token used to retrieve the conditional access policies.

    .Example
    PS C:\>Get-AADIntMSGraphConditionalAccessPolicies -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "identity/conditionalAccess/policies" -ApiVersion v1.0
    }
}

# Gets the cross tenant access policies
# Jul 22nd 2022
function Get-MSGraphCrossTenantAccessPolicy
{
    <#
    .SYNOPSIS
    Gets tenant's cross tenant access policies.

    .DESCRIPTION
    Gets tenant's cross tenant access policies.

    .PARAMETER AccessToken
    Access token used to retrieve the cross tenant access policies.

    .Example
    PS C:\>Get-AADIntMSGraphCrossTenantAccessPolicy -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "policies/crossTenantAccessPolicy" -ApiVersion v1.0
    }
}

# Gets the default cross tenant access policies
# Jul 22nd 2022
function Get-MSGraphCrossTenantAccessPolicyDefault
{
    <#
    .SYNOPSIS
    Gets tenant's default cross tenant access policies.

    .DESCRIPTION
    Gets tenant's default cross tenant access policies.

    .PARAMETER AccessToken
    Access token used to retrieve the default cross tenant access policies.

    .Example
    PS C:\>Get-AADIntMSGraphCrossTenantAccessPolicyDefault -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "policies/crossTenantAccessPolicy/default" -ApiVersion v1.0
    }
}

# Gets the cross tenant access policies partner
# Jul 22nd 2022
function Get-MSGraphCrossTenantAccessPolicyPartners
{
    <#
    .SYNOPSIS
    Gets tenant's cross tenant access policies partner.

    .DESCRIPTION
    Gets tenant's cross tenant access policies partner.

    .PARAMETER AccessToken
    Access token used to retrieve the cross tenant access policies partner.

    .Example
    PS C:\>Get-AADIntMSGraphCrossTenantAccessPolicyPartners -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "policies/crossTenantAccessPolicy/partners" -ApiVersion v1.0
    }
}

# Gets the current user authentication methods
# Jul 22nd 2022
function Get-MSGraphPersonalAuthenticationMethods
{
    <#
    .SYNOPSIS
    Gets tenant's current user authentication methods.

    .DESCRIPTION
    Gets tenant's current user authentication methods.

    .PARAMETER AccessToken
    Access token used to retrieve the current user authentication methods.

    .Example
    PS C:\>Get-AADIntMSGraphPersonalAuthenticationMethods -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "me/authentication/methods" -ApiVersion v1.0
    }
}

# Gets an user authentication methods
# Jul 22nd 2022
function Get-MSGraphUserAuthenticationMethods
{
    <#
    .SYNOPSIS
    Returns an user authentication methods.

    .DESCRIPTION
    Returns an user authentication methods.

    .PARAMETER AccessToken
    Access token used to get the user authentication methods

    .PARAMETER UserId
    User identifier or principal name

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphUserAuthenticationMethods -UserId "39429de5-4135-4ec3-ac2b-884f79b7ad5d" -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$UserId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserId/authentication/methods" -ApiVersion "v1.0" 
    }
}

# Gets the current user FIDO2 authentication methods
# Jul 22nd 2022
function Get-MSGraphPersonalFIDO2AuthenticationMethods
{
    <#
    .SYNOPSIS
    Gets tenant's current user FIDO2 authentication methods.

    .DESCRIPTION
    Gets tenant's current user FIDO2 authentication methods.

    .PARAMETER AccessToken
    Access token used to retrieve the current user FIDO2 authentication methods.

    .Example
    PS C:\>Get-AADIntMSGraphPersonalFIDO2AuthenticationMethods -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "me/authentication/fido2Methods" -ApiVersion v1.0
    }
}

# Gets an user FIDO2 authentication methods
# Jul 22nd 2022
function Get-MSGraphUserFIDO2AuthenticationMethods
{
    <#
    .SYNOPSIS
    Returns an user FIDO2 authentication methods.

    .DESCRIPTION
    Returns an user FIDO2 authentication methods.

    .PARAMETER AccessToken
    Access token used to get the user FIDO2 authentication methods

    .PARAMETER UserId
    User identifier or principal name

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphUserFIDO2AuthenticationMethods -UserId "39429de5-4135-4ec3-ac2b-884f79b7ad5d" -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$UserId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserId/authentication/fido2Methods" -ApiVersion "v1.0" 
    }
}

# Gets the current user Microsoft Authenticator authentication methods
# Jul 22nd 2022
function Get-MSGraphPersonalMicrosoftAuthenticatorAuthenticationMethods
{
    <#
    .SYNOPSIS
    Gets tenant's current user Microsoft Authenticator authentication methods.

    .DESCRIPTION
    Gets tenant's current user Microsoft Authenticator authentication methods.

    .PARAMETER AccessToken
    Access token used to retrieve the current user Microsoft Authenticator authentication methods.

    .Example
    PS C:\>Get-AADIntMSGraphPersonalMicrosoftAuthenticatorAuthenticationMethods -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "me/authentication/microsoftAuthenticatorMethods" -ApiVersion v1.0
    }
}

# Gets an user Microsoft Authenticator authentication methods
# Jul 22nd 2022
function Get-MSGraphUserMicrosoftAuthenticatorAuthenticationMethods
{
    <#
    .SYNOPSIS
    Returns an user Microsoft Authenticator authentication methods.

    .DESCRIPTION
    Returns an user Microsoft Authenticator authentication methods.

    .PARAMETER AccessToken
    Access token used to get the user Microsoft Authenticator authentication methods

    .PARAMETER UserId
    User identifier or principal name

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphUserMicrosoftAuthenticatorAuthenticationMethods -UserId "39429de5-4135-4ec3-ac2b-884f79b7ad5d" -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$UserId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserId/authentication/microsoftAuthenticatorMethods" -ApiVersion "v1.0" 
    }
}

# Gets the current user Windows Hello for business authentication methods
# Jul 22nd 2022
function Get-MSGraphPersonalWindowsHelloForBusinessMethodsAuthenticationMethods
{
    <#
    .SYNOPSIS
    Gets tenant's current user Windows Hello for business authentication methods.

    .DESCRIPTION
    Gets tenant's current user Windows Hello for business authentication methods.

    .PARAMETER AccessToken
    Access token used to retrieve the current user Windows Hello for business authentication methods.

    .Example
    PS C:\>Get-AADIntMSGraphPersonalWindowsHelloForBusinessAuthenticationMethods -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "me/authentication/windowsHelloForBusinessMethods" -ApiVersion v1.0
    }
}

# Gets an user Windows Hello for business authentication methods
# Jul 22nd 2022
function Get-MSGraphUserWindowsHelloForBusinessAuthenticationMethods
{
    <#
    .SYNOPSIS
    Returns an user Windows Hello for business authentication methods.

    .DESCRIPTION
    Returns an user Windows Hello for business authentication methods.

    .PARAMETER AccessToken
    Access token used to get the user Windows Hello for business authentication methods

    .PARAMETER UserId
    User identifier or principal name

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphUserWindowsHelloForBusinessAuthenticationMethods -UserId "39429de5-4135-4ec3-ac2b-884f79b7ad5d" -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$UserId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserId/authentication/windowsHelloForBusinessMethods" -ApiVersion "v1.0" 
    }
}

# Gets the current user temporary access path authentication methods
# Jul 22nd 2022
function Get-MSGraphPersonalTemporaryAccessPassAuthenticationMethods
{
    <#
    .SYNOPSIS
    Gets tenant's current user temporary access path authentication methods.

    .DESCRIPTION
    Gets tenant's current user temporary access path authentication methods.

    .PARAMETER AccessToken
    Access token used to retrieve the current user temporary access path authentication methods.

    .Example
    PS C:\>Get-AADIntMSGraphPersonalTemporaryAccessPassAuthenticationMethods -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "me/authentication/temporaryAccessPassMethods" -ApiVersion v1.0
    }
}

# Gets an user temporary access path authentication methods
# Jul 22nd 2022
function Get-MSGraphUserTemporaryAccessPassAuthenticationMethods
{
    <#
    .SYNOPSIS
    Returns an user temporary access path authentication methods.

    .DESCRIPTION
    Returns an user temporary access path authentication methods.

    .PARAMETER AccessToken
    Access token used to get the user temporary access path authentication methods

    .PARAMETER UserId
    User identifier or principal name

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphUserTemporaryAccessPassAuthenticationMethods -UserId "39429de5-4135-4ec3-ac2b-884f79b7ad5d" -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$UserId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "users/$UserId/authentication/temporaryAccessPassMethods" -ApiVersion "v1.0" 
    }
}

# Gets the organization
# Jul 22nd 2022
function Get-MSGraphOrganization
{
    <#
    .SYNOPSIS
    Gets tenant's organization.

    .DESCRIPTION
    Gets tenant's organization.

    .PARAMETER AccessToken
    Access token used to retrieve the organization.

    .Example
    PS C:\>Get-AADIntMSGraphOrganization -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "organization" -ApiVersion v1.0
    }
}

# Gets the organizational contacts
# Jul 22nd 2022
function Get-MSGraphOrganizationalContacts
{
    <#
    .SYNOPSIS
    Gets tenant's organizational contacts.

    .DESCRIPTION
    Gets tenant's organizational contacts.

    .PARAMETER AccessToken
    Access token used to retrieve the organizational contacts.

    .Example
    PS C:\>Get-AADIntMSGraphOrganizationalContacts -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "contacts" -ApiVersion v1.0
    }
}

# Gets an organizational contact
# Jul 22nd 2022
function Get-MSGraphOrganizationalContact
{
    <#
    .SYNOPSIS
    Returns an organizational contact.

    .DESCRIPTION
    Returns an organizational contact.

    .PARAMETER AccessToken
    Access token used to get the organizational contact

    .PARAMETER ContactId
    Contact identifier or principal name

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphOrganizationalContact -ContactId "" -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$UserId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "contacts/$ContactId" -ApiVersion "v1.0" 
    }
}

# Gets an organizational contact direct reports
# Jul 22nd 2022
function Get-MSGraphOrganizationalContactDirectReports
{
    <#
    .SYNOPSIS
    Returns an organizational contact direct reports.

    .DESCRIPTION
    Returns an organizational contact direct reports.

    .PARAMETER AccessToken
    Access token used to get the organizational contact direct reports

    .PARAMETER ContactId
    Contact identifier or principal name

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphOrganizationalContactDirectReports -ContactId "" -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$UserId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "contacts/$ContactId/directReports" -ApiVersion "v1.0" 
    }
}

# Gets an organizational contact membership
# Jul 22nd 2022
function Get-MSGraphOrganizationalContactMemberOf
{
    <#
    .SYNOPSIS
    Returns an organizational contact membership.

    .DESCRIPTION
    Returns an organizational contact membership.

    .PARAMETER AccessToken
    Access token used to get the organizational contact membership

    .PARAMETER ContactId
    Contact identifier or principal name

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphOrganizationalContactMemberOf -ContactId "" -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$UserId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "contacts/$ContactId/memberOf" -ApiVersion "v1.0" 
    }
}

# Gets an organizational contact manager
# Jul 22nd 2022
function Get-MSGraphOrganizationalContactManager
{
    <#
    .SYNOPSIS
    Returns an organizational contact manager.

    .DESCRIPTION
    Returns an organizational contact manager.

    .PARAMETER AccessToken
    Access token used to get the organizational contact manager

    .PARAMETER ContactId
    Contact identifier or principal name

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphOrganizationalContactManager -ContactId "" -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$UserId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "contacts/$ContactId/manager" -ApiVersion "v1.0" 
    }
}

# Gets the contracts
# Jul 22nd 2022
function Get-MSGraphContracts
{
    <#
    .SYNOPSIS
    Get contracts

    .DESCRIPTION
    Get contracts

    .PARAMETER AccessToken
    Access token used to retrieve the contracts

    .Example
    PS C:\>Get-AADIntMSGraphContracts -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "contracts" -ApiVersion beta
    }
}

# Gets the role definitions for the directory provider
# Jul 22nd 2022
function Get-MSGraphDirectoryRoleDefinitions
{
    <#
    .SYNOPSIS
    Returns the role definitions for the directory provider.

    .DESCRIPTION
    Returns the role definitions for the directory provider.

    .PARAMETER AccessToken
    Access token used to get the role definitions for the directory provider

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphDirectoryRoleDefinitions -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "roleManagement/directory/roleDefinitions" -ApiVersion v1.0
    }
}

# Gets the role definitions for the entitlement management provider
# Jul 22nd 2022
function Get-MSGraphEntitlementManagementRoleDefinitions
{
    <#
    .SYNOPSIS
    Returns the role definitions for the entitlement management provider.

    .DESCRIPTION
    Returns the role definitions for the entitlement management provider.

    .PARAMETER AccessToken
    Access token used to get the role definitions for the entitlement management provider

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphEntitlementManagementRoleDefinitions -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "roleManagement/entitlementManagement/roleDefinitions" -ApiVersion v1.0
    }
}

# Gets the role definition for the directory provider
# Jul 22nd 2022
function Get-MSGraphDirectoryRoleDefinition
{
    <#
    .SYNOPSIS
    Returns the role definition for the directory provider.

    .DESCRIPTION
    Returns the role definition for the directory provider.

    .PARAMETER AccessToken
    Access token used to get the role definition for the directory provider

    .PARAMETER RoleId
    Role identifier

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphUserMemberOf -AccessToken $AccessToken -UserId 64d999db-fc15-459c-bccf-5fa5908557aa # get a role identifier
    PS C:\>Get-AADIntMSGraphDirectoryRoleDefinition -AccessToken $AccessToken -RoleId 62e90394-69f5-4237-9190-012177145e10
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$RoleId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "roleManagement/directory/roleDefinitions/$RoleId" -ApiVersion v1.0
    }
}

# Gets the role definition for the entitlement management provider
# Jul 22nd 2022
function Get-MSGraphEntitlementManagementRoleDefinition
{
    <#
    .SYNOPSIS
    Returns the role definition for the entitlement management provider.

    .DESCRIPTION
    Returns the role definition for the entitlement management provider.

    .PARAMETER AccessToken
    Access token used to get the role definition for the entitlement management provider

    .PARAMETER RoleId
    Role identifier

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphUserMemberOf -AccessToken $AccessToken -UserId 64d999db-fc15-459c-bccf-5fa5908557aa # get a role identifier
    PS C:\>Get-AADIntMSGraphEntitlementManagementRoleDefinition -AccessToken $AccessToken -RoleId ""
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$RoleId
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "roleManagement/entitlementManagement/roleDefinitions/$RoleId" -ApiVersion v1.0
    }
}

# Gets the role assignments for the directory provider
# Jul 22nd 2022
function Get-MSGraphDirectoryRoleAssignments
{
    <#
    .SYNOPSIS
    Returns the role assignments for the directory provider.

    .DESCRIPTION
    Returns the role assignments for the directory provider.

    .PARAMETER AccessToken
    Access token used to get the role assignments for the directory provider

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphDirectoryRoleAssignments -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "roleManagement/directory/roleAssignments" -ApiVersion v1.0
    }
}

# Gets the role assignments for the entitlement management provider
# Jul 22nd 2022
function Get-MSGraphEntitlementManagementRoleAssignments
{
    <#
    .SYNOPSIS
    Returns the role assignments for the entitlement management provider.

    .DESCRIPTION
    Returns the role assignments for the entitlement management provider.

    .PARAMETER AccessToken
    Access token used to get the role assignments for the entitlement management provider

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphEntitlementManagementRoleAssignments -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "roleManagement/entitlementManagement/roleAssignments" -ApiVersion v1.0
    }
}

# Gets the role assignments schedule requests for the directory provider
# Jul 22nd 2022
function Get-MSGraphDirectoryRoleAssignmentScheduleRequests
{
    <#
    .SYNOPSIS
    Returns the role assignments schedule requests for the directory provider.

    .DESCRIPTION
    Returns the role assignments schedule requests for the directory provider.

    .PARAMETER AccessToken
    Access token used to get the role assignments schedule requests for the directory provider

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphDirectoryRoleAssignmentScheduleRequests -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "roleManagement/directory/roleAssignmentScheduleRequests" -ApiVersion v1.0
    }
}

# Gets the role assignments schedules for the directory provider
# Jul 22nd 2022
function Get-MSGraphDirectoryRoleAssignmentSchedules
{
    <#
    .SYNOPSIS
    Returns the role assignments schedules for the directory provider.

    .DESCRIPTION
    Returns the role assignments schedules for the directory provider.

    .PARAMETER AccessToken
    Access token used to get the role assignments schedules for the directory provider

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphDirectoryRoleAssignmentSchedules -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "roleManagement/directory/roleAssignmentSchedules" -ApiVersion v1.0
    }
}

# Gets the role assignments schedule instances for the directory provider
# Jul 22nd 2022
function Get-MSGraphDirectoryRoleAssignmentScheduleInstances
{
    <#
    .SYNOPSIS
    Returns the role assignments schedule instances for the directory provider.

    .DESCRIPTION
    Returns the role assignments schedule instances for the directory provider.

    .PARAMETER AccessToken
    Access token used to get the role assignments schedule instances for the directory provider

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphDirectoryRoleAssignmentScheduleInstances -AccessToken $AccessToken
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "roleManagement/directory/roleAssignmentScheduleInstances" -ApiVersion v1.0
    }
}

# Gets the role management policies
# Jul 22nd 2022
function Get-MSGraphRoleManagementPolicies
{
    <#
    .SYNOPSIS
    Returns the role management policies.

    .DESCRIPTION
    Returns the role management policies.

    .PARAMETER AccessToken
    Access token used to get the role management policies

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphRoleManagementPolicies -AccessToken $AccessToken -ScopeId '/' -ScopeType 'DirectoryRole'
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]$AccessToken,
        [Parameter(Mandatory = $True)]
        [String]$ScopeId,
        [Parameter(Mandatory = $True)]
        [String]$ScopeType
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Call-MSGraphAPI -AccessToken $AccessToken -API "policies/roleManagementPolicies" -ApiVersion v1.0 -QueryString "`$filter=scopeId eq '$ScopeId' and scopeType eq '$ScopeType'"
    }
}


## Export mailbox content (emails + attachments)
# Sep 4th 2025
function Get-MSGraphMailboxContent
{
    <#
    .SYNOPSIS
    Downloads all (or selected) mailbox emails and attachments via Microsoft Graph.

    .DESCRIPTION
    Enumerates mail folders for the signed-in (or specified) user mailbox, pages through all messages,
    saves each message as an .eml (raw MIME when permitted) plus a JSON metadata sidecar, and downloads attachments.
    Uses existing Call-MSGraphAPI for paging & throttling resilience. Large mailboxes can be filtered by date or folder.

    .PARAMETER AccessToken
    Access token with Mail.Read or equivalent permissions.

    .PARAMETER UserId
    Optional UPN or user id. If omitted, uses /me endpoints.

    .PARAMETER OutputPath
    Directory to store exported content. Created if missing. Structure: <OutputPath>\\<SanitizedUser>\\<FolderPath>\\

    .PARAMETER IncludeFolderNames
    Array of folder display names to include (case-insensitive). If empty/null, all folders.

    .PARAMETER ExcludeFolderNames
    Array of folder display names to exclude (case-insensitive).

    .PARAMETER Since
    Only export messages received on/after this (inclusive). (DateTime)

    .PARAMETER Until
    Only export messages received on/before this (inclusive). (DateTime)

    .PARAMETER FetchRawMime
    Attempt to download full MIME for each message (beta $value). Falls back to JSON body extract when fails.

    .PARAMETER MaxMessagesPerFolder
    Optional cap per folder to limit volume (for testing / sampling). 0 = unlimited.

    .PARAMETER SkipAttachments
    If set, do not download attachments.

    .EXAMPLE
    PS> Get-AADIntMSGraphMailboxContent -AccessToken $tok -UserId alice@contoso.com -OutputPath c:\temp\dump -Since (Get-Date).AddDays(-30) -FetchRawMime -Verbose
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$AccessToken,
        [Parameter(Mandatory=$false)]
        [string]$UserId,
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        [Parameter(Mandatory=$false)]
        [string[]]$IncludeFolderNames,
        [Parameter(Mandatory=$false)]
        [string[]]$ExcludeFolderNames,
        [Parameter(Mandatory=$false)]
        [datetime]$Since,
        [Parameter(Mandatory=$false)]
        [datetime]$Until,
        [Parameter(Mandatory=$false)]
        [switch]$FetchRawMime,
        [Parameter(Mandatory=$false)]
        [int]$MaxMessagesPerFolder=0,
        [Parameter(Mandatory=$false)]
        [switch]$SkipAttachments
    )
    Process
    {
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        if(-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath | Out-Null }

        $userSegment = if([string]::IsNullOrEmpty($UserId)) { 'me' } else { "users/$UserId" }
        $safeUser = if ($UserId) { $UserId } else { 'me' }
        $safeUser = $safeUser -replace '[^a-zA-Z0-9@._-]','_'
        $baseUserPath = Join-Path $OutputPath $safeUser
        if(-not (Test-Path $baseUserPath)) { New-Item -ItemType Directory -Path $baseUserPath | Out-Null }

        $includeSet = $null; if($IncludeFolderNames) { $includeSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase); $IncludeFolderNames | ForEach-Object { $includeSet.Add($_) | Out-Null } }
        $excludeSet = $null; if($ExcludeFolderNames) { $excludeSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase); $ExcludeFolderNames | ForEach-Object { $excludeSet.Add($_) | Out-Null } }

        Write-Verbose "Enumerating mail folders for $userSegment"
        $folders = @()
        try {
            $folders = Get-MSGraphMailFolders -AccessToken $AccessToken -UserId $UserId
        } catch { Write-Warning "Failed to enumerate folders: $_"; return }

        foreach($folder in $folders) {
            $fname = $folder.displayName
            if($includeSet -and -not $includeSet.Contains($fname)) { Write-Verbose "Skipping folder '$fname' (not in include set)"; continue }
            if($excludeSet -and $excludeSet.Contains($fname)) { Write-Verbose "Skipping folder '$fname' (in exclude set)"; continue }

            $folderPath = $fname -replace '[\\/:*?"<>|]','_'
            $folderOut = Join-Path $baseUserPath $folderPath
            if(-not (Test-Path $folderOut)) { New-Item -ItemType Directory -Path $folderOut | Out-Null }

            Write-Verbose "Exporting messages from folder '$fname'"

            # Build OData filter
            $filters = @()
            if($Since) { $filters += "receivedDateTime ge $($Since.ToUniversalTime().ToString('o'))" }
            if($Until) { $filters += "receivedDateTime le $($Until.ToUniversalTime().ToString('o'))" }
            $filterQs = if($filters.Count -gt 0) { "$filter=$([System.Web.HttpUtility]::UrlEncode([string]::Join(' and ',$filters)))" } else { $null }

            $api = "$userSegment/mailFolders/$($folder.id)/messages"
            $messages = @()
            try {
                $messages = Call-MSGraphAPI -AccessToken $AccessToken -API $api -ApiVersion "v1.0" -MaxResults 100000 -QueryString $filterQs
            } catch {
                Write-Warning "Failed to enumerate messages for folder ${fname}: $_"
                continue
            }

            $countExported = 0
            foreach($msg in $messages) {
                if($MaxMessagesPerFolder -gt 0 -and $countExported -ge $MaxMessagesPerFolder) { Write-Verbose "Reached cap $MaxMessagesPerFolder for folder '$fname'"; break }
                $msgId = $msg.id
                $received = $msg.receivedDateTime
                $subject = if($msg.subject) { $msg.subject } else { '(no subject)' }
                $safeSubject = $subject -replace '[\\/:*?"<>|]','_' -replace '\s+','_'
                $fileBase = "${received:yyyyMMdd_HHmmss}_${safeSubject}_${msgId.Substring(0,8)}"
                $metaPath = Join-Path $folderOut ($fileBase + '.json')
                $emlPath = Join-Path $folderOut ($fileBase + '.eml')

                if(Test-Path $metaPath) { Write-Verbose "Skipping message $msgId (already exported)"; continue }

                # Save metadata JSON
                $msg | ConvertTo-Json -Depth 6 | Out-File -FilePath $metaPath -Encoding UTF8

                if($FetchRawMime) {
                    $rawApi = "$userSegment/messages/$msgId/`$value"
                    try {
                        $mimeBytes = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/$rawApi" -Headers @{ Authorization = "Bearer $AccessToken" } -Method GET -ErrorAction Stop
                        if($mimeBytes) { [System.IO.File]::WriteAllBytes($emlPath, [System.Text.Encoding]::UTF8.GetBytes($mimeBytes)) }
                    } catch {
                        Write-Verbose "Raw MIME fetch failed for ${msgId}: $_ (will create simple EML)"
                    }
                }
                if(-not (Test-Path $emlPath)) {
                    # Fallback simple RFC822-ish representation
                    $lines = @()
                    $lines += "Subject: $subject"
                    $lines += "From: $($msg.from.emailAddress.address)"
                    $lines += "To: $([string]::Join(';', ($msg.toRecipients | ForEach-Object { $_.emailAddress.address })))"
                    $lines += "Date: $received"
                    $lines += "Message-ID: $msgId"
                    $lines += ""
                    $bodyContent = if($msg.body.content) { $msg.body.content } else { '' }
                    $lines += $bodyContent
                    $lines -join "`r`n" | Out-File -FilePath $emlPath -Encoding UTF8
                }

                if(-not $SkipAttachments) {
                    try {
                        $attApi = "$userSegment/messages/$msgId/attachments"
                        $attachments = Call-MSGraphAPI -AccessToken $AccessToken -API $attApi -ApiVersion "v1.0" -MaxResults 500
                        if($attachments) {
                            $attDir = Join-Path $folderOut ($fileBase + '_attachments')
                            if(-not (Test-Path $attDir)) { New-Item -ItemType Directory -Path $attDir | Out-Null }
                            foreach($att in $attachments) {
                                if($att.'@odata.type' -eq '#microsoft.graph.fileAttachment') {
                                    $aname = if($att.name) { $att.name } else { 'attachment' }
                                    $safeA = $aname -replace '[\\/:*?"<>|]','_'
                                    $aPath = Join-Path $attDir $safeA
                                    try { [System.IO.File]::WriteAllBytes($aPath, [System.Convert]::FromBase64String($att.contentBytes)) } catch { Write-Warning "Failed to write attachment $aname for ${msgId}: $_" }
                                } elseif($att.'@odata.type' -eq '#microsoft.graph.itemAttachment') {
                                    $subItemName = $att.name -replace '[\\/:*?"<>|]','_'
                                    $subMeta = Join-Path $attDir ($subItemName + '.json')
                                    $att | ConvertTo-Json -Depth 6 | Out-File -FilePath $subMeta -Encoding UTF8
                                }
                            }
                        }
                    } catch {
                        Write-Verbose "Attachment fetch failed for ${msgId}: $_"
                    }
                }

                $countExported++
            }
            Write-Verbose "Exported $countExported message(s) from '$fname'"
        }
    }
}

# Gets mail folders for a mailbox
# Sep 4th 2025
function Get-MSGraphMailFolders
{
    <#
    .SYNOPSIS
    Returns mail folders for the signed-in user or specified mailbox.

    .DESCRIPTION
    Simple wrapper around /me/mailFolders or /users/{id}/mailFolders using existing token cache helper.

    .PARAMETER AccessToken
    Access token with Mail.Read or related permissions.

    .PARAMETER UserId
    Optional user principal name or object id. If omitted, current user (me) is used.

    .PARAMETER MaxResults
    Maximum folders to return (paging via Call-MSGraphAPI). Default 5000.

    .EXAMPLE
    PS> Get-AADIntMSGraphMailFolders -AccessToken $tok

    .EXAMPLE
    PS> Get-AADIntMSGraphMailFolders -AccessToken $tok -UserId alice@contoso.com -Verbose
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$AccessToken,
        [Parameter(Mandatory=$false)]
        [string]$UserId,
        [Parameter(Mandatory=$false)]
        [int]$MaxResults=5000
    )
    Process
    {
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"
        $userSegment = if([string]::IsNullOrEmpty($UserId)) { 'me' } else { "users/$UserId" }
        Write-Verbose "Getting mail folders for $userSegment"
        try {
            Call-MSGraphAPI -AccessToken $AccessToken -API "$userSegment/mailFolders" -ApiVersion "v1.0" -MaxResults $MaxResults
        } catch {
            Write-Error "Failed to get mail folders: $_"
        }
    }
}

# Creates a mail rule
# Sep 5th 2025
function New-MSGraphPersonalMailRule
{
    <#
    .SYNOPSIS
    Creates (adds) a mailbox message rule via Microsoft Graph.

    .DESCRIPTION
    Wraps POST /users/{id}/mailFolders/inbox/messageRules (or /me/...) allowing the caller to pass a hashtable/psobject
    representing the rule body. Caller is responsible for providing valid conditions/actions per Graph schema.

    .PARAMETER AccessToken
    Access token with MailboxSettings.ReadWrite permissions.

    .PARAMETER UserId
    Optional UPN or object Id. If omitted, uses /me.

    .PARAMETER Rule
    Hashtable or PSCustomObject describing the rule (displayName, sequence, isEnabled, conditions, actions, exceptions, isReadOnly=false).

    .EXAMPLE
    $rule = @{ displayName = 'Move finance'; sequence = 1; isEnabled = $true; conditions = @{ subjectContains = @('invoice','payment') }; actions = @{ moveToFolder = '<folderId>'; stopProcessingRules = $true } }
    New-AADIntMSGraphMailRule -AccessToken $tok -UserId alice@contoso.com -MailFolderId $inboxId -Rule $rule -Verbose
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$false)] [string]$AccessToken,
        [Parameter(Mandatory=$false)] [string]$UserId,
        [Parameter(Mandatory=$true)]  [object]$Rule
    )
    Process
    {
        if(-not $Rule) { throw 'Rule parameter cannot be null.' }
        if($Rule -isnot [System.Collections.IDictionary] -and $Rule -isnot [pscustomobject]) { throw 'Rule must be a hashtable or PSCustomObject.' }

        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource 'https://graph.microsoft.com' -ClientId 'e9b154d0-7658-433b-bb25-6b8e0a8a7c59'
        $userSegment = if([string]::IsNullOrEmpty($UserId)) { 'me' } else { "users/$UserId" }

        # Serialize body
        $bodyJson = ($Rule | ConvertTo-Json -Depth 10)
    Write-Verbose "Creating inbox mail rule for $userSegment"

        $api = "$userSegment/mailFolders/inbox/messageRules"
        try {
            Call-MSGraphAPI -AccessToken $AccessToken -API $api -ApiVersion 'v1.0' -Method POST -Body $bodyJson -Headers @{ 'Content-Type' = 'application/json' }
        } catch {
            Write-Error "Failed to create mail rule: $_"
        }
    }
}

# Deletes a mail rule (by Id or displayName)
# Sep 5th 2025
function Remove-MSGraphPersonalMailRule
{
    <#
    .SYNOPSIS
    Deletes a mail rule by id or display name.

    .DESCRIPTION
    If RuleId is provided it is used directly. Otherwise the function enumerates inbox messageRules,
    finds the first rule whose displayName matches (case-insensitive) the provided DisplayName and deletes it.

    .PARAMETER AccessToken
    Access token with MailboxSettings.ReadWrite permissions.

    .PARAMETER UserId
    Optional user identifier (UPN/objectId). If omitted operates on /me.

    .PARAMETER RuleId
    Identifier of the rule to delete.

    .PARAMETER DisplayName
    Display name of the rule to delete (ignored if RuleId supplied). Match is case-insensitive exact.

    .PARAMETER Force
    Suppress confirmation prompt.

    .EXAMPLE
    Remove-AADIntMSGraphPersonalMailRule -AccessToken $tok -DisplayName "Delete keyworded mail"

    .EXAMPLE
    Remove-AADIntMSGraphPersonalMailRule -AccessToken $tok -RuleId a1b2c3d4-e5f6 -UserId user@contoso.com -Verbose
    #>
    [cmdletbinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    Param(
        [Parameter(Mandatory=$false)] [string]$AccessToken,
        [Parameter(Mandatory=$false)] [string]$UserId,
        [Parameter(Mandatory=$false)] [string]$RuleId,
        [Parameter(Mandatory=$false)] [string]$DisplayName,
        [Parameter(Mandatory=$false)] [switch]$Force
    )
    Process {
        if([string]::IsNullOrEmpty($RuleId) -and [string]::IsNullOrEmpty($DisplayName)) { throw 'Provide RuleId or DisplayName.' }

        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource 'https://graph.microsoft.com' -ClientId 'e9b154d0-7658-433b-bb25-6b8e0a8a7c59'
        $userSegment = if([string]::IsNullOrEmpty($UserId)) { 'me' } else { "users/$UserId" }

        if(-not $RuleId) {
            Write-Verbose 'Enumerating inbox rules to locate display name match.'
            try {
                $rules = Call-MSGraphAPI -AccessToken $AccessToken -API "$userSegment/mailFolders/inbox/messageRules" -ApiVersion 'v1.0' -MaxResults 500
            } catch { throw "Failed to enumerate rules: $_" }
            if(-not $rules) { throw 'No rules returned from inbox.' }
            $RuleId = ($rules | Where-Object { $_.displayName -and ($_.displayName -ieq $DisplayName) } | Select-Object -First 1).id
            if(-not $RuleId) { throw "No rule found with displayName '$DisplayName'" }
            Write-Verbose "Matched rule id $RuleId for displayName '$DisplayName'"
        }

        $api = "$userSegment/mailFolders/inbox/messageRules/$RuleId"
        if($PSCmdlet.ShouldProcess("$userSegment/$RuleId", 'Delete mail rule')) {
            try {
                Call-MSGraphAPI -AccessToken $AccessToken -API $api -ApiVersion 'v1.0' -Method DELETE
                Write-Verbose "Deleted mail rule $RuleId"
                [pscustomobject]@{ RuleId = $RuleId; Deleted = $true }
            } catch {
                throw "Failed to delete mail rule ${RuleId}: $_"
            }
        }
    }
}


# Creates a rule deleting messages whose subject/body contains specified keywords
# Sep 5th 2025
function New-MSGraphHidingRuleDeleteOnKeywords
{
    <#
    .SYNOPSIS
    Creates a message rule that deletes incoming mail when keywords appear in subject and/or body.

    .DESCRIPTION
    Builds a rule object and calls internal New-MSGraphPersonalMailRule (inbox scoped). Keywords matched per Graph
    message rule predicates using subjectContains and/or bodyContains arrays.

    .PARAMETER AccessToken
    Access token with MailboxSettings.ReadWrite permissions.

    .PARAMETER UserId
    Optional target user; if omitted uses /me.

    .PARAMETER Keywords
    One or more keyword strings to match.

    .PARAMETER MatchScope
    Where to match keywords: Subject, Body, or SubjectOrBody (default).

    .PARAMETER RuleName
    Display name for the rule (default: Delete keyworded mail).

    .PARAMETER Sequence
    Rule sequence number (default 1).

    .PARAMETER Disable
    If set, creates the rule disabled.

    .PARAMETER NoStopProcessing
    If set, does not stop further rule processing after a match.

    .EXAMPLE
    New-MSGraphHidingRuleDeleteOnKeywords -AccessToken $tok -UserId user@contoso.com -Keywords phishing urgent -MatchScope SubjectOrBody -Verbose
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$false)] [string]$AccessToken,
        [Parameter(Mandatory=$false)] [string]$UserId,
        [Parameter(Mandatory=$false)] [string[]]$Keywords=@('phishing','hack','spam'),
        [Parameter(Mandatory=$false)] [ValidateSet('Subject','Body','SubjectOrBody')] [string]$MatchScope='SubjectOrBody',
        [Parameter(Mandatory=$false)] [string]$RuleName='Delete keyworded mail',
        [Parameter(Mandatory=$false)] [int]$Sequence=1,
        [Parameter(Mandatory=$false)] [switch]$Disable,
        [Parameter(Mandatory=$false)] [switch]$NoStopProcessing
    )
    Process {
        if(-not $Keywords -or $Keywords.Count -eq 0) { throw 'Keywords parameter cannot be empty.' }
        # Build conditions
        $conditions = @{}
        switch($MatchScope) {
            'Subject' { $conditions.subjectContains = @($Keywords) }
            'Body'    { $conditions.bodyContains = @($Keywords) }
            'SubjectOrBody' { $conditions.bodyOrSubjectContains = @($Keywords) }
        }
        $actions = @{ permanentDelete = $true; stopProcessingRules = (-not $NoStopProcessing.IsPresent) }
        $rule = @{
            displayName = $RuleName
            sequence = $Sequence
            isEnabled = (-not $Disable.IsPresent)
            conditions = $conditions
            actions = $actions
            isReadOnly = $false
        }
        Write-Verbose "Creating delete rule '$RuleName' (scope: $MatchScope) for keywords: $($Keywords -join ',')"
        New-MSGraphPersonalMailRule -AccessToken $AccessToken -UserId $UserId -Rule $rule
    }
}

# Creates a hiding rule moving messages from specified senders to a folder and marking them read
# Sep 5th 2025
function New-MSGraphHidingRuleMoveOnSenders
{
    <#
    .SYNOPSIS
    Creates a message rule moving mail from listed senders to a target folder and marking them as read.

    .DESCRIPTION
    Uses senderContains predicate fragments to match sender (address/display name substring). Moves to provided folder id
    (must be an existing folder id) and marks mail as read. Invokes New-MSGraphPersonalMailRule (inbox scope).

    .PARAMETER AccessToken
    Access token with MailboxSettings.ReadWrite permissions.

    .PARAMETER UserId
    Optional target user; if omitted uses /me.

    .PARAMETER FromSenders
    One or more sender match fragments (e.g. full addresses or partial strings) applied to senderContains predicate.

    .PARAMETER TargetFolderId
    Destination folder id to move matching messages into. (Get-MSGraphMailFolders can help you find the folder id)

    .PARAMETER RuleName
    Display name (default: Move from senders).

    .PARAMETER Sequence
    Rule sequence number (default 1).

    .PARAMETER Disable
    If set, creates rule disabled.

    .PARAMETER NoStopProcessing
    If set, allows later rules to run after this one.

    .EXAMPLE
    New-AADIntMSGraphMailRuleMoveFromSenders -AccessToken $tok -UserId user@contoso.com -FromSenders bob@contoso.com hr@contoso.com -TargetFolderId <folderId>
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$false)] [string]$AccessToken,
        [Parameter(Mandatory=$false)] [string]$UserId,
        [Parameter(Mandatory=$true)]  [string[]]$FromSenders,
        [Parameter(Mandatory=$true)]  [string]$TargetFolderId,
        [Parameter(Mandatory=$false)] [string]$RuleName='Move from senders',
        [Parameter(Mandatory=$false)] [int]$Sequence=1,
        [Parameter(Mandatory=$false)] [switch]$Disable,
        [Parameter(Mandatory=$false)] [switch]$NoStopProcessing
    )
    Process {
        if(-not $FromSenders -or $FromSenders.Count -eq 0) { throw 'FromSenders cannot be empty.' }
        if([string]::IsNullOrEmpty($TargetFolderId)) { throw 'TargetFolderId is required.' }
        $conditions = @{ senderContains = @($FromSenders) }
        $actions = @{ moveToFolder = $TargetFolderId; markAsRead = $true; stopProcessingRules = (-not $NoStopProcessing.IsPresent) }
        $rule = @{
            displayName = $RuleName
            sequence = $Sequence
            isEnabled = (-not $Disable.IsPresent)
            conditions = $conditions
            actions = $actions
            isReadOnly = $false
        }
        Write-Verbose "Creating move rule '$RuleName' for senders: $($FromSenders -join ',') -> $TargetFolderId"
        New-MSGraphPersonalMailRule -AccessToken $AccessToken -UserId $UserId -Rule $rule
    }
}

# Forwards (redirects) all incoming messages to specified recipient(s)
# Sep 5th 2025
function New-MSGraphForwardingRuleForwardAll
{
    <#
    .SYNOPSIS
    Creates a message rule that redirects ALL incoming mail to one or more recipients.

    .DESCRIPTION
    Builds a rule object with no conditions so it matches every incoming message. Uses the redirectTo action by default.
    Optionally, -Forward can be supplied to use forwardTo (FW: prefix is added as opposed to redirecting). Stops further
    rule processing unless -NoStopProcessing is specified.

    NOTE: Forwarding/redirect rules may be restricted by tenant policies or disabled by administrators. Creation can
    fail with AccessDenied or similar errors in such cases.

    .PARAMETER AccessToken
    Access token with MailboxSettings.ReadWrite permissions.

    .PARAMETER UserId
    Optional target user; if omitted uses /me.

    .PARAMETER ForwardTo
    One or more SMTP addresses that should receive the messages.

    .PARAMETER Forward
    Use forwardTo instead of redirectTo (message appears as if directly delivered, no forward headers added).

    .PARAMETER RuleName
    Display name for the rule (default: Forward all mail).

    .PARAMETER Sequence
    Rule sequence number (default 1).

    .PARAMETER Disable
    If set, creates the rule disabled.

    .PARAMETER NoStopProcessing
    If set, allows subsequent rules to process after this rule.

    .EXAMPLE
    New-MSGraphHidingRuleForwardAll -AccessToken $tok -UserId user@contoso.com -ForwardTo archive@contoso.com -Verbose

    .EXAMPLE
    New-MSGraphHidingRuleForwardAll -AccessToken $tok -ForwardTo ext1@contoso.com ext2@contoso.com -Forward
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$false)] [string]$AccessToken,
        [Parameter(Mandatory=$false)] [string]$UserId,
        [Parameter(Mandatory=$true)]  [string[]]$ForwardTo,
        [Parameter(Mandatory=$false)] [switch]$Forward,
        [Parameter(Mandatory=$false)] [string]$RuleName='Forward all mail',
        [Parameter(Mandatory=$false)] [int]$Sequence=1,
        [Parameter(Mandatory=$false)] [switch]$Disable,
        [Parameter(Mandatory=$false)] [switch]$NoStopProcessing
    )
    Process {
        if(-not $ForwardTo -or $ForwardTo.Count -eq 0) { throw 'ForwardTo cannot be empty.' }

        # Build recipient objects as required by Graph (array of Recipient)
        $recipients = @()
        foreach($addr in $ForwardTo) {
            if([string]::IsNullOrWhiteSpace($addr)) { continue }
            $recipients += @{ emailAddress = @{ address = $addr.Trim() } }
        }
        if($recipients.Count -eq 0) { throw 'No valid recipient addresses provided.' }

        $actions = @{ stopProcessingRules = (-not $NoStopProcessing.IsPresent) }
        if($Forward.IsPresent) { $actions.forwardTo = $recipients } else { $actions.redirectTo = $recipients }

        $rule = @{
            displayName = $RuleName
            sequence = $Sequence
            isEnabled = (-not $Disable.IsPresent)
            actions = $actions
            isReadOnly = $false
        }

        Write-Verbose ("Creating forwarding rule '{0}' to recipients: {1}" -f $RuleName, ($ForwardTo -join ','))
        New-MSGraphPersonalMailRule -AccessToken $AccessToken -UserId $UserId -Rule $rule
    }
}

# Enumerates app registrations in the tenant
function Get-MSGraphApplicationRecon
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$AccessToken,
        [Parameter(Mandatory=$false)]
        [string]$ApplicationId
    )
    Process
    {
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

        Write-Verbose "Getting app registrations"
        $queryString = if ($ApplicationId) { "`$filter=appId eq '$ApplicationId'" } else { "" }
        $apps = Get-MSGraphApplications -AccessToken $AccessToken -QueryString $queryString

        $results = @()
        $sp_cache = @{}
        foreach ($app in $apps) {
            Write-Verbose "Processing app: $($app.displayName) ($($app.appId))"
            Write-Verbose "Getting owners"
            $owners = Get-MSGraphApplicationOwners -AccessToken $AccessToken -AppObjectId $app.id | Select-Object -Property id,userPrincipalName -ErrorAction SilentlyContinue

            Write-Verbose "Enumerating requested permissions"
            $requestedPermissions = @()
            foreach ($rra in $app.requiredResourceAccess) {
                $sp = Get-MSGraphServicePrincipals -AccessToken $AccessToken -QueryString "`$filter=appId eq '$($rra.resourceAppId)'" | Select-Object -First 1
                if ($sp -and -not $sp_cache.ContainsKey($sp.id)) {
                    $sp_cache[$sp.id] = $sp
                }

                $spRequestedPermissions = @()
                foreach ($ra in $rra.resourceAccess) {
                    $perm = $null
                    if ($ra.type -eq "Role") {
                        $perm = $sp.appRoles | Where-Object { $_.id -eq $ra.id } | Select-Object -First 1
                    } elseif ($ra.type -eq "Scope") {
                        $perm = $sp.oauth2PermissionScopes | Where-Object { $_.id -eq $ra.id } | Select-Object -First 1
                    }
                    if ($perm) {
                        $spRequestedPermissions += $perm.value
                    } else {
                        $spRequestedPermissions += $ra.id
                    }
                }
                $requestedPermissions += @{
                    ResourceAppId = $rra.resourceAppId
                    ResourceDisplayName = if ($sp) { $sp.displayName } else { 'Unknown' }
                    Permissions = $spRequestedPermissions -join ', '
                }
            }

            Write-Verbose "Getting admin consent grants"
            $sp = Get-MSGraphServicePrincipals -AccessToken $AccessToken -QueryString "`$filter=appId eq '$($app.appId)'" | Select-Object -First 1
            if ($sp) {
                $tenantWideConsentGrants = Get-MSGraphServicePrincipalPermissionGrants -AccessToken $AccessToken -ServicePrincipalId $sp.id | Where-Object { $_.consentType -eq "AllPrincipals" }
                $appOnlyPermissionGrants = Get-MSGraphServicePrincipalAppRoleAssignments -AccessToken $AccessToken -ServicePrincipalId $sp.id
            }

            Write-Verbose "Converting permissions to friendly names"
            #foreach ($perm in $tenantWideConsentGrants) {
            #    $perm_friendly = $sp_cache[$perm.resourceId].oauth2PermissionScopes | Where-Object { $_.id -eq $perm.id } | Select-Object -First 1
            #    if ($perm_friendly) {
            #        $perm | Add-Member -MemberType NoteProperty -Name scopeFriendly -Value $perm_friendly.value
            #    }
            #}
            foreach ($perm in $appOnlyPermissionGrants) {
                $perm_friendly = $sp_cache[$perm.resourceId].appRoles | Where-Object { $_.id -eq $perm.appRoleId } | Select-Object -First 1
                if ($perm_friendly) {
                    $perm | Add-Member -MemberType NoteProperty -Name appRoleFriendly -Value $perm_friendly.value
                }
            }

            $results += [pscustomobject]@{
                AppId = $app.appId
                DisplayName = $app.displayName
                ObjectId = $app.id
                Owners = $owners
                APIPermissionsRequested = $requestedPermissions
                TenantWideConsentGrants = $tenantWideConsentGrants
                AppOnlyPermissionGrants = $appOnlyPermissionGrants
                AppRoles = $app.appRoles
            }
        }

        return $results
    }
}


# Add password credential to an app registration
function New-MSGraphApplicationPassword
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$AccessToken,
        [Parameter(Mandatory=$true)]
        [string]$AppObjectId,
        [Parameter(Mandatory=$false)]
        [string]$DisplayName,
        [Parameter(Mandatory=$false)]
        [datetime]$EndDateTime
    )
    Process
    {
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1950a258-227b-4e31-a9cf-717495945fc2"

        $body = @{ passwordCredential = @{} }
        if ($DisplayName) {
            $body.passwordCredential.displayName = $DisplayName
        }
        if ($EndDateTime) {
            $body.passwordCredential.endDateTime = $EndDateTime
        }

        Call-MSGraphAPI -AccessToken $AccessToken -API "applications/$AppObjectId/addPassword" -ApiVersion "v1.0" -Method POST -Body ($body | ConvertTo-Json -Depth 5) -Headers @{ 'Content-Type' = 'application/json' }
    }
}

# Removes a password credential from an app registration
function Remove-MSGraphApplicationPassword
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$AccessToken,
        [Parameter(Mandatory=$true)]
        [string]$AppObjectId,
        [Parameter(Mandatory=$true)]
        [string]$KeyId
    )
    Process
    {
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1950a258-227b-4e31-a9cf-717495945fc2"

        $body = @{ keyId = $KeyId }

        Call-MSGraphAPI -AccessToken $AccessToken -API "applications/$AppObjectId/removePassword" -ApiVersion "v1.0" -Method POST -Body ($body | ConvertTo-Json -Depth 5) -Headers @{ 'Content-Type' = 'application/json' }
    }
}