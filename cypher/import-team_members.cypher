LOAD CSV WITH HEADERS FROM 'file:///team_members.csv' AS row
MERGE (tm:TeamMember {
    id: row.id
})
SET tm.roles=row.roles,
    tm.displayName=row.displayName,
    tm.visibleHistoryStartDateTime=datetime(row.visibleHistoryStartDateTime),
    tm.email=row.email,
    tm.tenantId=row.tenantId
MERGE (t:Team {id: row.groupId})
MERGE (tm)-[r1:BELONGS_TO]-(t)
MERGE (u:User {id: row.userId})
MERGE (u)-[r2:JOINED_TEAM]-(t)
MERGE (u)-[r3:TEAM_PROFILE]-(tm)