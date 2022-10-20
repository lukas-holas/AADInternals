LOAD CSV WITH HEADERS FROM 'file:///audit_log_target_resources_modified_properties.csv' AS row
MERGE (m:AuditLogTargetResourceModifiedProperty {
    id: apoc.util.md5([row.displayName, row.auditLogId, row.targetResourceId])
})
SET m.displayName=row.displayName,
    m.oldValue=row.oldValue,
    m.newValue=row.newValue // "" when empty, not null
MERGE (t:AuditLogTargetResource {id: row.targetResourceId})
MERGE (t)-[r1:MODIFIED_PROPERTY]-(m)
MERGE (a:AuditLog {id: row.auditLogId})
MERGE (a)-[r2:MODIFIED_PROPERTY]-(m)