# This script contains utility functions to map the active directory using the MSGraph API

function Export-AzureADToCSV
{
    <#
    .SYNOPSIS
    Export the active directory content to CSV.

    .DESCRIPTION
    Export the active directory content to CSV.

    .PARAMETER AccessToken
    Access token used to get the team information.

    .PARAMETER Directory
    Directory where to save the CSV files.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Export-AADIntAzureADToCSV -AccessToken $AccessToken -Directory .\Files\
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$AccessToken,
        [Parameter(Mandatory = $False)]
        [String]$Directory = ""
    )
    Process
    {
        # Get from cache if not provided
        $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -Resource "https://graph.microsoft.com" -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894"

        Write-Host "Get the personal informations"
        $currentUser = Get-AADIntMSGraphPersonalUser -AccessToken $AccessToken
        $currentUser | ConvertTo-User |
            Export-Csv -NoTypeInformation -Path $Directory"current_user.csv" -Encoding UTF8

        $personalPeople = Get-MSGraphPersonalPeople -AccessToken $AccessToken | Where-Object {$_} 
        $personalPeopleUsers = $personalPeople | Where-Object {$_.personType.class -eq "Person"} | ConvertTo-People | Where-Object {$_}
        $personalPeopleUsers | Add-Member -MemberType NoteProperty -Name personalId -Value $currentUser.id
        $personalPeopleUsers | Export-Csv -NoTypeInformation -Path $Directory"personal_people_users.csv" -Encoding UTF8
        $personalPeopleGroups = $personalPeople | Where-Object {$_.personType.class -eq "Group"} | ConvertTo-People | Where-Object {$_}
        $personalPeopleGroups | Add-Member -MemberType NoteProperty -Name personalId -Value $currentUser.id
        $personalPeopleGroups | Export-Csv -NoTypeInformation -Path $Directory"personal_people_groups.csv" -Encoding UTF8
        
        $personalMemberOf = Get-MSGraphPersonalMemberOf -AccessToken $AccessToken
        $personalMemberOfRoles = $personalMemberOf | Where-Object "@odata.type" -eq "#microsoft.graph.directoryRole" | ConvertTo-Role
        $personalMemberOfRoles | Add-Member -MemberType NoteProperty -Name personalId -Value $currentUser.id
        $personalMemberOfRoles | Export-Csv -NoTypeInformation -Path $Directory"personal_roles.csv" -Encoding UTF8
        
        $personalMemberOfGroups = $personalMemberOf | Where-Object "@odata.type" -eq "#microsoft.graph.group" | ConvertTo-Group 
        $personalMemberOfGroups | Add-Member -MemberType NoteProperty -Name personalId -Value $currentUser.id
        $personalMemberOfGroups | Export-Csv -NoTypeInformation -Path $Directory"personal_groups.csv" -Encoding UTF8

        $personalJoinedTeams = Get-MSGraphPersonalJoinedTeams -AccessToken $AccessToken | Where-Object {$_} | ConvertTo-JoinedTeam 
        $personalJoinedTeams | Where-Object {$_} | Add-Member -MemberType NoteProperty -Name personalId -Value $currentUser.id
        $personalJoinedTeams | Export-Csv -NoTypeInformation -Path $Directory"personal_joinedteams.csv" -Encoding UTF8

        $personalShared = Get-MSGraphPersonalShared -AccessToken $AccessToken | ConvertTo-Shared 
        $personalShared | Add-Member -MemberType NoteProperty -Name personalId -Value $currentUser.id
        $personalShared | Export-Csv -NoTypeInformation -Path $Directory"personal_shared.csv" -Encoding UTF8

        $personalShared.id | Where-Object {$_} | ForEach-Object {
            $sharedInsight = Get-AADIntMSGraphSharedResource -AccessToken $AccessToken -SharedInsightId $_ |
                ConvertTo-GroupDriveItemContent
            $sharedInsight | Add-Member -MemberType NoteProperty -Name sharedInsightId -Value $_
            $sharedInsight
        } | Export-Csv -NoTypeInformation -Path $Directory"personal_sharedinsights.csv" -Encoding UTF8

        Get-MSGraphPersonalRootFolder -AccessToken $AccessToken | Where-Object {$_} | 
            ConvertTo-GroupRootDrive | Export-Csv -NoTypeInformation -Path $Directory"personal_rootfolder.csv" -Encoding UTF8

        $personalDriveItemsContent = Get-MSGraphPersonalDriveItemsContent -AccessToken $AccessToken -ErrorAction Continue
        # if @odata.context then root folder
        # $personalRootDrive = $personalDriveItemsContent | Where-Object "@odata.context" | ConvertTo-GroupRootDrive
        # $personalRootDrive | Export-Csv -NoTypeInformation -Path $Directory"personal_rootfolder.csv" -Encoding UTF8
        # if @microsoft.graph.downloadUrl then file
        $personalFiles = $personalDriveItemsContent | Where-Object "@microsoft.graph.downloadUrl" | ConvertTo-GroupDriveItemContent 
        $personalFiles | Add-Member -MemberType NoteProperty -Name personalId -Value $currentUser.id
        $personalFiles | Export-Csv -NoTypeInformation -Path $Directory"personal_drivefiles.csv" -Encoding UTF8
        # else then folder
        $personalFolders = $personalDriveItemsContent | Where-Object {!$_."@microsoft.graph.downloadUrl" -and !$_."@odata.context"} | 
            Where-Object {$_} | ConvertTo-GroupDriveItem 
        $personalFolders | Where-Object {$_} | Add-Member -MemberType NoteProperty -Name personalId -Value $currentUser.id
        $personalFolders | Export-Csv -NoTypeInformation -Path $Directory"personal_drivefolders.csv" -Encoding UTF8

        Write-Host "Get all the users"
        $users = Get-MSGraphUsers -AccessToken $AccessToken | ConvertTo-User 
        $users | Export-Csv -NoTypeInformation -Path $Directory"users.csv" -Encoding UTF8

        Write-Host "Get the joined teams"
        $users.id | ForEach-Object {
            $joinedteam = Get-MSGraphJoinedTeams -AccessToken $AccessToken -UserId $_ | Where-Object {$_} |
                ConvertTo-JoinedTeam
            $joinedteam | Where-Object {$_} | Add-Member -MemberType NoteProperty -Name userId -Value $_
            $joinedteam
        } | Export-Csv -NoTypeInformation -Path $Directory"users_joinedteams.csv" -Encoding UTF8

        Write-Host "Get the shared documents"
        $usersShared = @()
        $usersSharedInsight = @()
        $users.id | ForEach-Object {
            $userShared = Get-MSGraphShared -AccessToken $AccessToken -UserId $_ -ErrorAction SilentlyContinue | Where-Object {$_} |
                ConvertTo-Shared
            $userShared | Where-Object {$_} | Add-Member -MemberType NoteProperty -Name userId -Value $_
            $usersShared += $userShared

            $userShared.id | Where-Object {$_} | ForEach-Object {
                $userSharedInsight = Get-AADIntMSGraphSharedResource -AccessToken $AccessToken -SharedInsightId $_ |
                    ConvertTo-GroupDriveItemContent
                $userSharedInsight | Add-Member -MemberType NoteProperty -Name sharedInsightId -Value $_
                $usersSharedInsight += $userSharedInsight
            }
        } 
        $usersShared | Export-Csv -NoTypeInformation -Path $Directory"users_shared.csv" -Encoding UTF8
        $usersSharedInsight | Export-Csv -NoTypeInformation -Path $Directory"users_sharedinsights.csv" -Encoding UTF8

        Write-Host "Get the related people"
        $peopleUsers = @()
        $peopleGroups = @()
        $users.id | ForEach-Object {
            $people = Get-MSGraphPeople -AccessToken $AccessToken -UserId $_ -ErrorAction SilentlyContinue | Where-Object {$_} 

            $peopleUser = $people | Where-Object {$_.personType.class -eq "Person"} | ConvertTo-People | Where-Object {$_}
            $peopleUser | Add-Member -MemberType NoteProperty -Name userId -Value $_
            $peopleUsers += $peopleUser

            $peopleGroup = $people | Where-Object {$_.personType.class -eq "Group"} | ConvertTo-People | Where-Object {$_}
            $peopleGroup | Add-Member -MemberType NoteProperty -Name userId -Value $_
            $peopleGroups += $peopleGroup
        } 
        $peopleUsers | Export-Csv -NoTypeInformation -Path $Directory"users_people_users.csv" -Encoding UTF8
        $peopleGroups | Export-Csv -NoTypeInformation -Path $Directory"users_people_groups.csv" -Encoding UTF8

        Write-Host "Get the users' informations"
        $users.id | ForEach-Object {
            Get-MSGraphUser -AccessToken $AccessToken -UserId $_ |
                ConvertTo-User
        } | Export-Csv -NoTypeInformation -Path $Directory"users_informations.csv" -Encoding UTF8

        Write-Host "Get the users' groups and roles"
        $usersMemberOfRoles = @()
        $usersMemberOfGroups = @()
        $users.id | ForEach-Object {
            $userMemberOf = Get-MSGraphUserMemberOf -AccessToken $AccessToken -UserId $_
            
            $userMemberOfRole = $userMemberOf | Where-Object "@odata.type" -eq "#microsoft.graph.directoryRole" | ConvertTo-Role
            $userMemberOfRole | Add-Member -MemberType NoteProperty -Name userId -Value $_
            $usersMemberOfRoles += $userMemberOfRole
            
            $userMemberOfGroup = $userMemberOf | Where-Object "@odata.type" -eq "#microsoft.graph.group" | ConvertTo-Group 
            $userMemberOfGroup | Add-Member -MemberType NoteProperty -Name userId -Value $_
            $usersMemberOfGroups += $userMemberOfGroup
        }
        $usersMemberOfRoles | Export-Csv -NoTypeInformation -Path $Directory"users_roles.csv" -Encoding UTF8
        $usersMemberOfGroups | Export-Csv -NoTypeInformation -Path $Directory"users_groups.csv" -Encoding UTF8

        Write-Host "Get the users' groups and roles (transitive)"
        $usersTransitiveMemberOfRoles = @()
        $usersTransitiveMemberOfGroups = @()
        $users.id | ForEach-Object {
            $userTransitiveMemberOf = Get-MSGraphUserTransitiveMemberOf -AccessToken $AccessToken -UserId $_
            
            $userTransitiveMemberOfRole = $userTransitiveMemberOf | Where-Object "@odata.type" -eq "#microsoft.graph.directoryRole" | ConvertTo-Role
            $userTransitiveMemberOfRole | Add-Member -MemberType NoteProperty -Name userId -Value $_
            $usersTransitiveMemberOfRoles += $userTransitiveMemberOfRole
            
            $userTransitiveMemberOfGroup = $userTransitiveMemberOf | Where-Object "@odata.type" -eq "#microsoft.graph.group" | ConvertTo-Group 
            $userTransitiveMemberOfGroup | Add-Member -MemberType NoteProperty -Name userId -Value $_
            $usersTransitiveMemberOfGroups += $userTransitiveMemberOfGroup
        }
        $usersTransitiveMemberOfRoles | Export-Csv -NoTypeInformation -Path $Directory"users_transitiveroles.csv" -Encoding UTF8
        $usersTransitiveMemberOfGroups | Export-Csv -NoTypeInformation -Path $Directory"users_transitivegroups.csv" -Encoding UTF8

        Write-Host "Get all the groups"
        $groups = Get-MSGraphGroups -AccessToken $AccessToken | ConvertTo-Group 
        $groups | Export-Csv -NoTypeInformation -Path $Directory"groups.csv" -Encoding UTF8

        Write-Host "Get the teams"
        $groups.id | ForEach-Object {
            # remove the error warning and filter for null value in the pipe
            Get-MSGraphTeam -AccessToken $AccessToken -GroupId $_ -ErrorAction SilentlyContinue | Where-Object {$_} | 
                ConvertTo-Team
        } | Export-Csv -NoTypeInformation -Path $Directory"team.csv" -Encoding UTF8
        
        Write-Host "Get the teams members"
        $groups.id | ForEach-Object {
            # remove the error warning and filter for null value in the pipe
            $teamMember = Get-MSGraphTeamMembers -AccessToken $AccessToken -GroupId $_ -ErrorAction SilentlyContinue | Where-Object {$_} | 
                ConvertTo-TeamMember
            $teamMember | Where-Object {$_} | Add-Member -MemberType NoteProperty -Name groupId -Value $_
            $teamMember
        } | Export-Csv -NoTypeInformation -Path $Directory"team_members.csv" -Encoding UTF8

        Write-Host "Get the groups members"
        $groups.id | ForEach-Object {
            $groupMember = Get-MSGraphGroupMembers -AccessToken $AccessToken -GroupId $_ | 
                Where-Object "@odata.type" -eq "#microsoft.graph.user" | 
                ConvertTo-User
            $groupMember | Add-Member -MemberType NoteProperty -Name groupId -Value $_
            $groupMember
        } | Export-Csv -NoTypeInformation -Path $Directory"group_members.csv" -Encoding UTF8

        Write-Host "Get the groups owners"
        $groups.id | ForEach-Object {
            $groupOwner = Get-MSGraphGroupOwners -AccessToken $AccessToken -GroupId $_ | 
                Where-Object "@odata.type" -eq "#microsoft.graph.user" | 
                ConvertTo-User
            $groupOwner | Add-Member -MemberType NoteProperty -Name groupId -Value $_
            $groupOwner
        } | Export-Csv -NoTypeInformation -Path $Directory"group_owners.csv" -Encoding UTF8

        Write-Host "Get the groups root drives"
        $groups.id | ForEach-Object {
            Get-MSGraphGroupRootFolder -AccessToken $AccessToken -GroupId $_ | 
                ConvertTo-GroupRootDrive
        } | Export-Csv -NoTypeInformation -Path $Directory"group_rootfolder.csv" -Encoding UTF8

        Write-Host "Get the groups drives"
        $groups.id | ForEach-Object {
            Get-MSGraphGroupDrives -AccessToken $AccessToken -GroupId $_ | 
                ConvertTo-GroupDrive
        } | Export-Csv -NoTypeInformation -Path $Directory"group_drives.csv" -Encoding UTF8

        Write-Host "Get the groups files"
        # $groupsRootDrive = @()
        $groupsFiles = @()
        $groupsFolders = @()
        $groups.id | ForEach-Object {
            $groupDriveItemsContent = Get-MSGraphGroupDriveItemsContent -AccessToken $AccessToken -GroupId $_ -ErrorAction Continue
            # if @odata.context then root folder
            # $groupRootDrive = $groupDriveItemsContent | Where-Object "@odata.context" | ConvertTo-GroupRootDrive 
            # $groupRootDrive | Add-Member -MemberType NoteProperty -Name groupId -Value $_
            # $groupsRootDrive += $groupRootDrive
            # if @microsoft.graph.downloadUrl then file
            $groupFiles = $groupDriveItemsContent | Where-Object "@microsoft.graph.downloadUrl" | ConvertTo-GroupDriveItemContent 
            $groupFiles | Where-Object {$_} | Add-Member -MemberType NoteProperty -Name groupId -Value $_
            $groupsFiles += $groupFiles
            # else then folder
            $groupFolders = $groupDriveItemsContent | Where-Object {!$_."@microsoft.graph.downloadUrl" -and !$_."@odata.context" -and $_.folder} | 
                ConvertTo-GroupDriveItem 
            $groupFolders | Where-Object {$_} | Add-Member -MemberType NoteProperty -Name groupId -Value $_
            $groupsFolders += $groupFolders
        }
        # $groupsRootDrive | Export-Csv -NoTypeInformation -Path $Directory"group_rootfolder.csv" -Encoding UTF8
        $groupsFiles | Export-Csv -NoTypeInformation -Path $Directory"group_drivefiles.csv" -Encoding UTF8
        $groupsFolders | Export-Csv -NoTypeInformation -Path $Directory"group_drivefolders.csv" -Encoding UTF8

        Write-Host "Get the role members"
        $usersMemberOfRoles.id | Where-Object {$_} | Select-Object -Unique | ForEach-Object {
            # remove the error warning and filter for null value in the pipe
            $roleMember = Get-MSGraphRoleMembers -AccessToken $AccessToken -RoleId $_ -ErrorAction SilentlyContinue | Where-Object {$_} | 
                ConvertTo-User
            $roleMember | Where-Object {$_} | Add-Member -MemberType NoteProperty -Name roleId -Value $_
            $roleMember
        } | Export-Csv -NoTypeInformation -Path $Directory"role_members.csv" -Encoding UTF8

        Write-Host "Get the audit log"
        $auditLog = Get-AzureAuditLog -AccessToken $AccessToken -Export
        $auditLog | ConvertTo-DirectoryAuditLog |
            Export-Csv -NoTypeInformation -Path $Directory"audit_log.csv" -Encoding UTF8
        
        $targetResources = @()
        $targetResourcesModifiedProperties = @()
        $auditLog | ForEach-Object {
            $auditLogId = $_.id
            $targetResource = $_.targetResources | ConvertTo-DirectoryAuditLogTargetResource
            $targetResource | Add-Member -MemberType NoteProperty -Name auditLogId -Value $auditLogId
            $targetResources += $targetResource

            $_.targetResources | ForEach-Object {
                $targetResourceModifiedProperties = $_.modifiedProperties | ConvertTo-DirectoryAuditLogTargetResourceModifiedProperties
                $targetResourceModifiedProperties | Add-Member -MemberType NoteProperty -Name targetResourceId -Value $_.id
                $targetResourceModifiedProperties | Add-Member -MemberType NoteProperty -Name auditLogId -Value $auditLogId
                $targetResourcesModifiedProperties += $targetResourceModifiedProperties
            }
        }
        $targetResources | Export-Csv -NoTypeInformation -Path $Directory"audit_log_target_resources.csv" -Encoding UTF8
        $targetResourcesModifiedProperties | Export-Csv -NoTypeInformation -Path $Directory"audit_log_target_resources_modified_properties.csv" -Encoding UTF8

        Write-Host "Get the delegated permissions grant"
        Get-MSGraphDelegatedPermissionGrants -AccessToken $AccessToken | Export-Csv -NoTypeInformation -Path $Directory"delegated_permissions_grant.csv" -Encoding UTF8

        Write-Host "Get the service principals"
        $servicePrincipals = Get-MSGraphServicePrincipals -AccessToken $AccessToken
        $servicePrincipals | ConvertTo-ServicePrincipals |
            Export-Csv -NoTypeInformation -Path $Directory"service_principals.csv" -Encoding UTF8

        $appRoles = @()
        $permissionScopes = @()
        $appRolesAssignedTo = @()
        $servicePrincipals | ForEach-Object {
            $servicePrincipalId = $_.id
            $appRole = $_.appRoles | ConvertTo-ServicePrincipalsAppRoles
            $appRole | Add-Member -MemberType NoteProperty -Name servicePrincipalId -Value $servicePrincipalId
            $appRoles += $appRole

            $permissionScope = $_.oauth2PermissionScopes | ConvertTo-ServicePrincipalsPermissionScopes
            $permissionScope | Add-Member -MemberType NoteProperty -Name servicePrincipalId -Value $servicePrincipalId
            $permissionScopes += $permissionScope

            $appRolesAssignedTo += Get-MSGraphServicePrincipalAppRoleAssignedTo -AccessToken $AccessToken -ServicePrincipalId $servicePrincipalId | ConvertTo-ServicePrincipalAppRoleAssignedTo
        }
        $appRoles | Export-Csv -NoTypeInformation -Path $Directory"app_roles.csv" -Encoding UTF8
        $permissionScopes | Export-Csv -NoTypeInformation -Path $Directory"permission_scopes.csv" -Encoding UTF8
        $appRolesAssignedTo | Export-Csv -NoTypeInformation -Path $Directory"app_roles_assigned_to.csv" -Encoding UTF8
    }
}

# Filter the shared items
# Jul 01st 2022
function ConvertTo-Shared
{
    <#
    .SYNOPSIS
    Filter the shared items.

    .DESCRIPTION
    Filter the shared items returned from Get-AADIntMSGraphShared or Get-AADIntMSGraphPersonalShared

    .PARAMETER Data
    Data to be filtered.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphPersonalShared -AccessToken $AccessToken | ConvertTo-AADIntShared
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline)]
        [Object]$Data
    )
    Process
    {
        $Data | Select-Object -Property id, 
            @{n='sharedDateTime';e={$_.lastShared.sharedDateTime}},
            @{n='title';e={$_.resourceVisualization.title}},
            @{n='containerWebUrl';e={$_.resourceVisualization.containerWebUrl}},
            @{n='containerDisplayName';e={$_.resourceVisualization.containerDisplayName}},
            @{n='containerType';e={$_.resourceVisualization.containerType}},
            @{n='resourceWebUrl';e={$_.resourceReference.webUrl}},
            @{n='resourceId';e={$_.resourceReference.id}},
            @{n='resourceType';e={$_.resourceReference.type}}
    }
}

# Filter the related people
# Jul 01st 2022
function ConvertTo-People
{
    <#
    .SYNOPSIS
    Filter the related people.

    .DESCRIPTION
    Filter the related people returned from Get-AADIntMSGraphPeople or Get-AADIntMSGraphPersonalPeople

    .PARAMETER Data
    Data to be filtered.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphPersonalPeople -AccessToken $AccessToken | ConvertTo-AADIntPeople
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline)]
        [Object]$Data
    )
    Process
    {
        $Data | Select-Object -Property id, 
            displayName,
            givenName,
            surname,
            birthday,
            personNotes,
            isFavorite,
            jobTitle,
            companyName,
            department,
            officeLocation,
            profession,
            userPrincipalName,
            imAddress,
            @{n='scoredEmailAddresses';e={$($_.scoredEmailAddresses).address}},
            @{n='phones';e={$_.phones.number}},
            @{n='relevanceScore';e={$_.scoredEmailAddresses.relevanceScore}},
            @{n='class';e={$_.personType.class}},
            @{n='subclass';e={$_.personType.subclass}}
    }
}

# Filter the team
# Jul 01st 2022
function ConvertTo-Team
{
    <#
    .SYNOPSIS
    Filter the team 

    .DESCRIPTION
    Filter the team returned from Get-AADIntMSGraphTeam

    .PARAMETER Data
    Data to be filtered.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphTeam -GroupId aa9ea6fd-6b09-4b70-9ba6-34551068a8d0 -AccessToken $AccessToken | ConvertTo-AADIntTeam
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline)]
        [Object]$Data
    )
    Process
    {
        $Data | Select-Object -Property id, 
            createdDateTime,
            description,
            internalId,
            displayName,
            specialization,
            visibility,
            webUrl,
            isArchived,
            isMembershipLimitedToOwners,
            @{n='memberSettingsAllowCreateUpdateChannels';e={$_.memberSettings.allowCreateUpdateChannels}},
            @{n='memberSettingsAllowDeleteChannels';e={$_.memberSettings.allowDeleteChannels}},
            @{n='memberSettingsAllowCreatePrivateChannels';e={$_.memberSettings.allowCreatePrivateChannels}},
            @{n='memberSettingsAllowAddRemoveApps';e={$_.memberSettings.allowAddRemoveApps}},
            @{n='memberSettingsAllowCreateUpdateRemoveTabs';e={$_.memberSettings.allowCreateUpdateRemoveTabs}},
            @{n='memberSettingsAllowCreateUpdateRemoveConnectors';e={$_.memberSettings.allowCreateUpdateRemoveConnectors}},
            @{n='guestSettingsAllowCreateUpdateChannels';e={$_.guestSettings.allowCreateUpdateChannels}},
            @{n='guestSettingsAllowDeleteChannels';e={$_.guestSettings.allowDeleteChannels}},
            @{n='discoverySettingsShowInTeamsSearchAndSuggestions';e={$_.discoverySettings.showInTeamsSearchAndSuggestions}},
            @{n='summaryOwnersCount';e={$_.summary.ownersCount}},
            @{n='summaryMembersCount';e={$_.summary.membersCount}},
            @{n='summaryGuestsCount';e={$_.summary.guestsCount}}
    }
}

# Filter the team members
# Jul 01st 2022
function ConvertTo-TeamMember
{
    <#
    .SYNOPSIS
    Filter the team members.

    .DESCRIPTION
    Filter the team members returned from Get-AADIntMSGraphTeamMembers.
    "@odata.type" is always "#microsoft.graph.aadUserConversationMember"
    See https://docs.microsoft.com/en-us/graph/api/team-list-members?view=graph-rest-1.0&tabs=http.

    .PARAMETER Data
    Data to be filtered.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphTeamMembers -GroupId aa9ea6fd-6b09-4b70-9ba6-34551068a8d0 -AccessToken $AccessToken | ConvertTo-AADIntTeamMember
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline)]
        [Object]$Data
    )
    Process
    {
        $Data | Select-Object -Property id,
            @{n='roles';e={$_.roles -join ','}},
            displayName,
            visibleHistoryStartDateTime,
            userId,
            email,
            tenantId
    }
}

# Filter the joined teams
# Jul 01st 2022
function ConvertTo-JoinedTeam
{
    <#
    .SYNOPSIS
    Filter the joined teams.

    .DESCRIPTION
    Filter the joined teams returned from Get-AADIntMSGraphJoinedTeams or Get-AADIntMSGraphPersonalJoinedTeams
    It may be replace by ConvertTo-Team in the future (same input by less data).

    .PARAMETER Data
    Data to be filtered.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphPersonalJoinedTeams -AccessToken $AccessToken | ConvertTo-AADIntJoinedTeam
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline)]
        [Object]$Data
    )
    Process
    {
        $Data | Select-Object -Property id, 
            createdDateTime,
            description,
            internalId,
            displayName,
            webUrl,
            isArchived,
            isMembershipLimitedToOwners,
            visibility
    }
}

# Filter the group
# Jul 01st 2022
function ConvertTo-Group
{
    <#
    .SYNOPSIS
    Filter the group.

    .DESCRIPTION
    Filter the group returned from Get-AADIntMSGraphGroups, Get-AADIntMSGraphUserMemberOf, Get-AADIntMSGraphUserTransitiveMemberOf or Get-AADIntMSGraphPersonalMemberOf

    .PARAMETER Data
    Data to be filtered.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphGroups -AccessToken $AccessToken | ConvertTo-AADIntGroup
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline)]
        [Object]$Data
    )
    Process
    {
        $Data | Select-Object -Property id, 
            createdDateTime,
            @{n='creationOptions';e={$_.creationOptions -join ','}},
            renewedDateTime,
            description,
            displayName,
            expirationDateTime,
            mail,
            mailEnabled,
            mailNickname,
            @{n='proxyAddresses';e={$_.proxyAddresses -join ','}},
            @{n='resourceBehaviorOptions';e={$_.resourceBehaviorOptions -join ','}},
            @{n='resourceProvisioningOptions';e={$_.resourceProvisioningOptions -join ','}},
            securityEnabled,
            securityIdentifier,
            visibility
    }
}

# Filter the role
# Jul 01st 2022
function ConvertTo-Role
{
    <#
    .SYNOPSIS
    Filter the role.

    .DESCRIPTION
    Filter the role returned from Get-AADIntMSGraphUserMemberOf, Get-AADIntMSGraphUserTransitiveMemberOf or Get-AADIntMSGraphPersonalMemberOf

    .PARAMETER Data
    Data to be filtered.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphPersonalMemberOf -AccessToken $AccessToken | 
        Where-Object "@odata.type" -eq "#microsoft.graph.directoryRole" | 
        ConvertTo-AADIntRole
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline)]
        [Object]$Data
    )
    Process
    {
        $Data | Select-Object -Property id, 
            deletedDateTime,
            description,
            displayName
    }
}

# Filter the group members or owners
# Jul 01st 2022
function ConvertTo-User
{
    <#
    .SYNOPSIS
    Filter the group members or owners.

    .DESCRIPTION
    Filter the group members or owners returned from Get-AADIntMSGraphGroupMember or Get-AADIntMSGraphGroupOwners

    .PARAMETER Data
    Data to be filtered.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphGroupMembers -AccessToken $AccessToken -GroupId 2c150da4-603f-4348-a886-624f8aaf4b49 | ConvertTo-AADIntUser
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline)]
        [Object]$Data
    )
    Process
    {
        $Data | Select-Object -Property id, 
            @{n='businessPhones';e={$_.businessPhones -join ','}},
            displayName,
            givenName,
            surname,
            jobTitle,
            mail,
            mobilePhone,
            officeLocation,
            userPrincipalName,
            onPremisesDistinguishedName,
            onPremisesImmutableId,
            onPremisesLastSyncDateTime,
            onPremisesSamAccountName,
            refreshTokensValidFromDateTime,
            signInSessionsValidFromDateTime,
            usageLocation,
            @{n='proxyAddresses';e={$_.proxyAddresses -join ','}},
            @{n='provisionedPlans';e={$($_.provisionedPlans.service | Select-Object -Unique) -join ","}}
    }
}

# Filter the root drive
# Jul 01st 2022
function ConvertTo-GroupRootDrive
{
    <#
    .SYNOPSIS
    Filter the root drive.

    .DESCRIPTION
    Filter the root drive returned from Get-AADIntMSGraphGroupRootFolder or Get-AADIntMSGraphPersonalRootFolder

    .PARAMETER Data
    Data to be filtered.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphPersonalRootFolder -AccessToken $AccessToken | ConvertTo-AADIntGroupRootDrive
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline)]
        [Object]$Data
    )
    Process
    {
        $Data | Select-Object -Property id, 
            createdDateTime,
            lastModifiedDateTime,
            name,
            webUrl,
            size,
            @{n='parentReferenceDriveId';e={$_.parentReference.driveId}},
            @{n='folder';e={$_.folder.childCount}}
    }
}

# Filter the group drive
# Jul 01st 2022
function ConvertTo-GroupDrive
{
    <#
    .SYNOPSIS
    Filter the group drive.

    .DESCRIPTION
    Filter the group drive returned from Get-AADIntMSGraphGroupDrives

    .PARAMETER Data
    Data to be filtered.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphGroupDrives -GroupId "aa9ea6fd-6b09-4b70-9ba6-34551068a8d0" -AccessToken $AccessToken | ConvertTo-AADIntGroupDrive
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline)]
        [Object]$Data
    )
    Process
    {
        $Data | Select-Object -Property id, 
            createdDateTime,
            lastModifiedDateTime,
            description,
            name,
            webUrl,
            @{n='createdByUserId';e={$_.createdBy.user.id}},
            @{n='createdByUserEmail';e={$_.createdBy.user.email}},
            @{n='createdByUserDisplayName';e={$_.createdBy.user.displayName}},
            @{n='lastModifiedByUserId';e={$_.lastModifiedBy.user.id}},
            @{n='lastModifiedByUserEmail';e={$_.lastModifiedBy.user.email}},
            @{n='lastModifiedByUserDisplayName';e={$_.lastModifiedBy.user.displayName}},
            @{n='ownerGroupId';e={$_.owner.group.id}},
            @{n='ownerGroupEmail';e={$_.owner.group.email}},
            @{n='ownerGroupDisplayName';e={$_.owner.group.displayName}},
            @{n='quotaUsed';e={$_.quota.used}},
            @{n='quotaRemaining';e={$_.quota.remaining}}
    }
}

# Filter the group drive item
# Jul 01st 2022
function ConvertTo-GroupDriveItem
{
    <#
    .SYNOPSIS
    Filter the group drive item.

    .DESCRIPTION
    Filter the group drive item returned from Get-AADIntMSGraphPersonalDriveItems or Get-AADIntMSGraphGroupDriveItems

    .PARAMETER Data
    Data to be filtered.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphPersonalDriveItems -DriveId "017F7BVQF6Y2GOVW7725BZO354PWSELRRZ" -AccessToken $AccessToken | ConvertTo-AADIntGroupDriveItem
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline)]
        [Object]$Data
    )
    Process
    {
        $Data | Select-Object -Property id, 
            createdDateTime,
            lastModifiedDateTime,
            name,
            webUrl,
            size,
            @{n='createdByUser';e={$_.createdBy.user.id}},
            @{n='createdByApplication';e={$_.createdBy.application.id}},
            @{n='lastModifiedByUser';e={$_.lastModifiedBy.user.id}},
            @{n='lastModifiedByApplication';e={$_.lastModifiedBy.application.id}},
            @{n='parentReferenceDriveId';e={$_.parentReference.driveId}},
            @{n='parentReferenceId';e={$_.parentReference.id}},
            @{n='parentReferencePath';e={$_.parentReference.path}},
            @{n='folder';e={$_.folder.childCount}}
    }
}

# Filter the group drive item content
# Jul 01st 2022
function ConvertTo-GroupDriveItemContent
{
    <#
    .SYNOPSIS
    Filter the group drive item content.

    .DESCRIPTION
    Filter the group drive item content returned from Get-AADIntMSGraphGroupDriveItemsContent, Get-AADIntMSGraphGroupsDriveItemsContent, Get-AADIntMSGraphSharedResource
    or Get-AADIntMSGraphPersonalDriveItemsContent

    .PARAMETER Data
    Data to be filtered.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphPersonalDriveItemsContent -AccessToken $AccessToken | ConvertTo-AADIntGroupDriveItemContent
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline)]
        [Object]$Data
    )
    Process
    {
        $Data | Select-Object -Property @{n='microsoftGraphDownloadUrl';e={$_."@microsoft.graph.downloadUrl"}},
            id, 
            createdDateTime,
            lastModifiedDateTime,
            name,
            webUrl,
            size,
            @{n='createdByUser';e={$_.createdBy.user.id}},
            @{n='createdByApplication';e={$_.createdBy.application.id}},
            @{n='lastModifiedByUser';e={$_.lastModifiedBy.user.id}},
            @{n='lastModifiedByApplication';e={$_.lastModifiedBy.application.id}},
            @{n='parentReferenceDriveId';e={$_.parentReference.driveId}},
            @{n='parentReferenceId';e={$_.parentReference.id}},
            @{n='parentReferencePath';e={$_.parentReference.path}},
            @{n='sharedScope';e={$_.shared.scope}}
    }
}

# Filter the directory audit log
# Jul 01st 2022
function ConvertTo-DirectoryAuditLog
{
    <#
    .SYNOPSIS
    Filter the directory audit log.

    .DESCRIPTION
    Filter the directory audit log returned from Get-AADIntAzureAuditLog

    .PARAMETER Data
    Data to be filtered.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntAzureAuditLog -AccessToken $AccessToken -Export | ConvertTo-AADIntDirectoryAuditLog
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline)]
        [Object]$Data
    )
    Process
    {
        $Data | Select-Object -Property id, 
            category,
            correlationId,
            result,
            resultReason,
            activityDisplayName,
            activityDateTime,
            loggedByService,
            operationType,
            userAgent,
            @{n='initiatedByUserId';e={$_.initiatedBy.user.id}},
            @{n='initiatedByUserDisplayName';e={$_.initiatedBy.user.displayName}},
            @{n='initiatedByUserUserPrincipalName';e={$_.initiatedBy.user.userPrincipalName}},
            @{n='initiatedByUserIPAddress';e={$_.initiatedBy.user.ipAddress}},
            @{n='initiatedByUserUserType';e={$_.initiatedBy.user.userType}},
            @{n='initiatedByUserHomeTenantId';e={$_.initiatedBy.user.homeTenantId}},
            @{n='initiatedByUserHomeTenantName';e={$_.initiatedBy.user.homeTenantName}},
            @{n='initiatedByAppId';e={$_.initiatedBy.app.id}}
    }
}

# Filter the directory audit log target resource
# Jul 01st 2022
function ConvertTo-DirectoryAuditLogTargetResource
{
    <#
    .SYNOPSIS
    Filter the directory audit log target resource.

    .DESCRIPTION
    Filter the directory audit log target resource returned from Get-AADIntAzureAuditLog

    .PARAMETER Data
    Data to be filtered.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>$(Get-AADIntAzureAuditLog -AccessToken $AccessToken -Export).targetResources | ConvertTo-AADIntDirectoryAuditLogTargetResource
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline)]
        [Object]$Data
    )
    Process
    {
        $Data | Select-Object -Property id,
            displayName,
            type,
            userPrincipalName,
            groupType
    }
}

# Filter the directory audit log target resource modified properties
# Jul 01st 2022
function ConvertTo-DirectoryAuditLogTargetResourceModifiedProperties
{
    <#
    .SYNOPSIS
    Filter the directory audit log target resource modified properties.

    .DESCRIPTION
    Filter the directory audit log target resource modified properties returned from Get-AADIntAzureAuditLog

    .PARAMETER Data
    Data to be filtered.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>$(Get-AADIntAzureAuditLog -AccessToken $AccessToken -Export).targetResources.modifiedProperties | ConvertTo-AADIntDirectoryAuditLogTargetResourceModifiedProperties
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline)]
        [Object]$Data
    )
    Process
    {
        $Data | Select-Object -Property displayName,
            oldValue,
            newValue
    }
}

# Filter the service principals
# Jul 01st 2022
function ConvertTo-ServicePrincipals
{
    <#
    .SYNOPSIS
    Filter the service principals.

    .DESCRIPTION
    Filter the service principals returned from Get-MSGraphServicePrincipals or Get-MSGraphServicePrincipal

    .PARAMETER Data
    Data to be filtered.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>$(Get-AADIntMSGraphServicePrincipals -AccessToken $AccessToken) | ConvertTo-AADIntServicePrincipals
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline)]
        [Object]$Data
    )
    Process
    {
        $Data | Select-Object -Property id,
            deletedDateTime,
            accountEnabled,
            @{n='alternativeNames';e={$_.alternativeNames -join ','}},
            appDisplayName,
            appDescription,
            appId,
            applicationTemplateId,
            appOwnerOrganizationId,
            appRoleAssignmentRequired,
            createdDateTime,
            description,
            disabledByMicrosoftStatus,
            displayName,
            homepage,
            loginUrl,
            logoutUrl,
            notes,
            @{n='notificationEmailAddresses';e={$_.notificationEmailAddresses -join ','}},
            preferredSingleSignOnMode,
            preferredTokenSigningKeyThumbprint,
            @{n='replyUrls';e={$_.replyUrls -join ','}},
            @{n='servicePrincipalNames';e={$_.servicePrincipalNames -join ','}},
            servicePrincipalType,
            signInAudience,
            @{n='tags';e={$_.tags -join ','}},
            tokenEncryptionKeyId,
            samlSingleSignOnSettings,
            @{n='verifiedPublisherDisplayName';e={$_.verifiedPublisher.displayName}},
            @{n='verifiedPublisherId';e={$_.verifiedPublisher.verifiedPublisherId}},
            @{n='verifiedPublisherAddedDateTime';e={$_.verifiedPublisher.addedDateTime}},
            @{n='logoUrl';e={$_.info.logoUrl}},
            @{n='marketingUrl';e={$_.info.marketingUrl}},
            @{n='privacyStatementUrl';e={$_.info.privacyStatementUrl}},
            @{n='supportUrl';e={$_.info.supportUrl}},
            @{n='termsOfServiceUrl';e={$_.info.termsOfServiceUrl}}
    }
}

# Filter the service principals app roles
# Jul 01st 2022
function ConvertTo-ServicePrincipalsAppRoles
{
    <#
    .SYNOPSIS
    Filter the service principals app roles.

    .DESCRIPTION
    Filter the service principals app roles returned from Get-MSGraphServicePrincipals or Get-MSGraphServicePrincipal

    .PARAMETER Data
    Data to be filtered.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>$(Get-AADIntMSGraphServicePrincipals -AccessToken $AccessToken).appRoles | ConvertTo-AADIntServicePrincipalsAppRoles
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline)]
        [Object]$Data
    )
    Process
    {
        $Data | Select-Object -Property id,
            displayName,
            description,
            isEnabled,
            origin,
            value,
            @{n='allowedMemberTypes';e={$_.allowedMemberTypes -join ','}}
    }
}

# Filter the service principals permission scopes
# Jul 01st 2022
function ConvertTo-ServicePrincipalsPermissionScopes
{
    <#
    .SYNOPSIS
    Filter the service principals permission scopes.

    .DESCRIPTION
    Filter the service principals permission scopes returned from Get-MSGraphServicePrincipals or Get-MSGraphServicePrincipal

    .PARAMETER Data
    Data to be filtered.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>$(Get-AADIntMSGraphServicePrincipals -AccessToken $AccessToken).oauth2PermissionScopes | ConvertTo-AADIntServicePrincipalsPermissionScopes
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline)]
        [Object]$Data
    )
    Process
    {
        $Data | Select-Object -Property id,
            adminConsentDescription,
            adminConsentDisplayName,
            isEnabled,
            type,
            userConsentDescription,
            userConsentDisplayName,
            value
    }
}

# Filter the service principals permission scopes
# Jul 01st 2022
function ConvertTo-ServicePrincipalAppRoleAssignedTo
{
    <#
    .SYNOPSIS
    Filter the service principals permission scopes.

    .DESCRIPTION
    Filter the service principals permission scopes returned from Get-MSGraphServicePrincipalAppRoleAssignedTo

    .PARAMETER Data
    Data to be filtered.

    .Example
    PS C:\>$AccessToken = Get-AADIntAccessTokenFromCache -Resource "https://graph.microsoft.com" -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    PS C:\>Get-AADIntMSGraphServicePrincipalAppRoleAssignedTo -AccessToken $AccessToken -ServicePrincipalId 8ab7851b-6672-4999-b2ee-d2caf46b4c8f | ConvertTo-AADIntServicePrincipalAppRoleAssignedTo
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline)]
        [Object]$Data
    )
    Process
    {
        $Data | Select-Object -Property id,
            appRoleId,
            createdDateTime,
            principalDisplayName,
            principalId,
            principalType,
            resourceDisplayName,
            resourceId
    }
}