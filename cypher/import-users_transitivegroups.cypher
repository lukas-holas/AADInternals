// TODO: almost the same as import-personal_groups.cypher (param userId instead of personalId)
// TODO: same as import-users_groups.cypher
LOAD CSV WITH HEADERS FROM 'file:///users_transitivegroups.csv' AS row
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
MERGE (u:User {id: row.userId})
MERGE (u)-[r:BELONGS_TO]-(g)