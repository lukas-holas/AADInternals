LOAD CSV WITH HEADERS FROM 'file:///audit_log_target_resources.csv' AS row
MERGE (t:AuditLogTargetResource {
    id: row.id
})
SET t.displayName=row.displayName,
    t.type=row.type,
    t.userPrincipalName=row.userPrincipalName,
    t.groupType=row.groupType
MERGE (a:AuditLog {id: row.auditLogId})
MERGE (a)-[r:TARGET_RESOURCE]-(t)