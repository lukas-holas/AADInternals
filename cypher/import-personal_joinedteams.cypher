LOAD CSV WITH HEADERS FROM 'file:///personal_joinedteams.csv' AS row
MERGE (t:Team {
    id: row.id
})
SET t.createdDateTime=datetime(row.createdDateTime),
    t.displayName=row.displayName,
    t.description=row.description, // "" when empty, not null
    t.internalId=row.internalId,
    t.webUrl=row.webUrl,
    t.isArchived=row.isArchived,
    t.isMembershipLimitedToOwners=toBoolean(row.isMembershipLimitedToOwners),
    t.visibility=row.visibility
MERGE (u:User {id: row.personalId})
MERGE (u)-[r:JOINED_TEAM]-(t)