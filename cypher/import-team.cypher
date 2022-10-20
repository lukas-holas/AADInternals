LOAD CSV WITH HEADERS FROM 'file:///team.csv' AS row
MERGE (t:Team {
    id: row.id
})
SET t.createdDateTime=datetime(row.createdDateTime),
    t.displayName=row.displayName,
    t.description=row.description, // "" when empty, not null
    t.internalId=row.internalId,
    t.specialization=row.specialization,
    t.webUrl=row.webUrl,
    t.isArchived=row.isArchived,
    t.isMembershipLimitedToOwners=toBoolean(row.isMembershipLimitedToOwners),
    t.memberSettingsAllowCreateUpdateChannels=toBoolean(row.memberSettingsAllowCreateUpdateChannels),
    t.memberSettingsAllowDeleteChannels=toBoolean(row.memberSettingsAllowDeleteChannels),
    t.memberSettingsAllowCreatePrivateChannels=toBoolean(row.memberSettingsAllowCreatePrivateChannels),
    t.memberSettingsAllowAddRemoveApps=toBoolean(row.memberSettingsAllowAddRemoveApps),
    t.memberSettingsAllowCreateUpdateRemoveTabs=toBoolean(row.memberSettingsAllowCreateUpdateRemoveTabs),
    t.memberSettingsAllowCreateUpdateRemoveConnectors=toBoolean(row.memberSettingsAllowCreateUpdateRemoveConnectors),
    t.guestSettingsAllowCreateUpdateChannels=toBoolean(row.guestSettingsAllowCreateUpdateChannels),
    t.guestSettingsAllowDeleteChannels=toBoolean(row.guestSettingsAllowDeleteChannels),
    t.discoverySettingsShowInTeamsSearchAndSuggestions=toBoolean(row.discoverySettingsShowInTeamsSearchAndSuggestions),
    t.summaryOwnersCount=toInteger(row.summaryOwnersCount),
    t.summaryMembersCount=toInteger(row.summaryMembersCount),
    t.summaryGuestsCount=toInteger(row.summaryGuestsCount),
    t.visibility=row.visibility
MERGE (g:Group {id: t.id})
MERGE (g)-[r:HAS_TEAM]-(t)