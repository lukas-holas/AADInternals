LOAD CSV WITH HEADERS FROM 'file:///app_roles_assigned_to.csv' AS row
MERGE (a:AppRoleAssignment {
    id: row.id
})
MERGE (s:ServicePrincipal {id: row.resourceId})
SET s.displayName=row.resourceDisplayName
MERGE (a)-[r1:ASSIGNED_FOR]-(s)
MERGE (r:AppRole {id: row.appRoleId})
MERGE (r)-[r2:ASSIGNMENT]-(a)

WITH row WHERE row.principalType="User"
MERGE (u:User {id: row.principalId})
SET u.displayName=row.principalDisplayName
MERGE (r:AppRole {id: row.appRoleId})
MERGE (r)-[r3:ASSIGNED_TO]-(u)
SET r3.createdDateTime = datetime(row.createdDateTime)

WITH row WHERE row.principalType="Group"
MERGE (g:Group {id: row.principalId})
SET g.displayName=row.principalDisplayName
MERGE (r:AppRole {id: row.appRoleId})
MERGE (r)-[r4:ASSIGNED_TO]-(g)
SET r4.createdDateTime = datetime(row.createdDateTime)

WITH row WHERE row.principalType="ServicePrincipal"
MERGE (s:ServicePrincipal {id: row.principalId})
SET s.displayName=row.principalDisplayName
MERGE (r:AppRole {id: row.appRoleId})
MERGE (r)-[r5:ASSIGNED_TO]-(s)
SET r5.createdDateTime = datetime(row.createdDateTime)