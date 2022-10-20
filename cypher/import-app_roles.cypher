LOAD CSV WITH HEADERS FROM 'file:///app_roles.csv' AS row
MERGE (r:AppRole {
    id: row.id
})
SET r.displayName=row.displayName,
    r.description=row.description,
    r.isEnabled=toBoolean(row.isEnabled),
    r.origin=row.origin,
    r.allowedMemberTypes=row.allowedMemberTypes,
    r.value=row.value
MERGE (s:ServicePrincipal {id: row.servicePrincipalId})
MERGE (s)-[r1:APPLICATION_ROLE]-(r)