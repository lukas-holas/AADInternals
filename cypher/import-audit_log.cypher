LOAD CSV WITH HEADERS FROM 'file:///audit_log.csv' AS row
MERGE (a:AuditLog {
    id: row.id
})
SET a.category=row.category,
    a.correlationId=row.correlationId,
    a.result=row.result,
    a.resultReason=row.resultReason, // "" when empty, not null
    a.activityDisplayName=row.activityDisplayName,
    a.activityDateTime=datetime(row.activityDateTime),
    a.loggedByService=row.loggedByService,
    a.operationType=row.operationType,
    a.userAgent=row.userAgent,
    a.initiatedByUserId=row.initiatedByUserId,
    a.initiatedByUserDisplayName=row.initiatedByUserDisplayName,
    a.initiatedByUserUserPrincipalName=row.initiatedByUserUserPrincipalName,
    a.initiatedByUserIPAddress=row.initiatedByUserIPAddress,
    a.initiatedByUserUserType=row.initiatedByUserUserType, // "" when empty, not null
    a.initiatedByUserHomeTenantId=row.initiatedByUserHomeTenantId,
    a.initiatedByUserHomeTenantName=row.initiatedByUserHomeTenantName,
    a.initiatedByAppId=row.initiatedByAppId