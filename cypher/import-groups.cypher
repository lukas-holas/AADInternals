LOAD CSV WITH HEADERS FROM 'file:///groups.csv' AS row
MERGE (g:Group {
    id: row.id
})
SET g.createdDateTime=datetime(row.createdDateTime), 
    g.creationOptions=row.creationOptions, // "" when empty, not null
    g.renewedDateTime=datetime(row.renewedDateTime),
    g.displayName=row.displayName,
    g.description=row.description, // "" when empty, not null
    g.mail=row.mail,
    g.mailEnabled=toBoolean(row.mailEnabled),
    g.mailNickname=row.mailNickname,
    g.expirationDateTime=datetime(row.expirationDateTime),
    g.resourceBehaviorOptions=row.resourceBehaviorOptions, // "" when empty, not null
    g.resourceProvisioningOptions=row.resourceProvisioningOptions, // "" when empty, not null
    g.securityEnabled=toBoolean(row.securityEnabled),
    g.securityIdentifier=row.securityIdentifier,
    g.visibility=row.visibility,
    g.proxyAddresses=row.proxyAddresses