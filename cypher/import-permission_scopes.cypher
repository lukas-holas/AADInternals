LOAD CSV WITH HEADERS FROM 'file:///permission_scopes.csv' AS row
MERGE (p:PermissionScope {
    id: row.id
})
SET p.adminConsentDescription=row.adminConsentDescription,
    p.adminConsentDisplayName=row.adminConsentDisplayName,
    p.isEnabled=toBoolean(row.isEnabled),
    p.type=row.type,
    p.userConsentDescription=row.userConsentDescription,
    p.userConsentDisplayName=row.userConsentDisplayName,
    p.value=row.value
MERGE (s:ServicePrincipal {id: row.servicePrincipalId})
MERGE (s)-[r1:PERMISSION_SCOPE]-(p)