LOAD CSV WITH HEADERS FROM 'file:///delegated_permissions_grant.csv' AS row
MERGE (d:DelegatedPermissionGrant {
    id: row.id
})
SET d.consentType=row.consentType,
    d.scope=row.scope
MERGE (s1:ServicePrincipal {id: row.clientId})
MERGE (s1)-[r1:HAS_DELEGATED_PERMISSION]-(d)
MERGE (s2:ServicePrincipal {id: row.resourceId})
MERGE (d)-[r3:AUTHORIZED_RESOURCE]-(s2)

WITH row WHERE row.principalId IS NOT null
MERGE (u:User {id: row.principalId})
MERGE (d:DelegatedPermissionGrant {id: row.id})
MERGE (u)-[r2:GRANTED_PERMISSION]-(d)
