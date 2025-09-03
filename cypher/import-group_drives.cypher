LOAD CSV WITH HEADERS FROM 'file:///group_drives.csv' AS row
MERGE (drive:Drive {
    id: row.id
})
SET drive.createdDateTime=datetime(row.createdDateTime),
    drive.lastModifiedDateTime=datetime(row.lastModifiedDateTime),
    drive.webUrl=row.webUrl,
    drive.name=row.name,
    drive.description=row.description,
    drive.createdByUserDisplayName=row.createdByUserDisplayName,
    drive.quotaUsed=toInteger(row.quotaUsed),
    drive.quotaRemaining=toInteger(row.quotaRemaining)
MERGE (g:Group {
    id: row.ownerGroupId
})
SET g.mail=row.ownerGroupEmail,
    g.displayName=row.ownerGroupDisplayName
MERGE (g)-[r1:HAS_DRIVE]-(drive)

WITH row WHERE row.lastModifiedByUserId IS NOT null
MERGE (drive:Drive {
    id: row.id
})
MERGE (u:User {
    id: row.lastModifiedByUserId
})
SET u.mail=row.lastModifiedByUserEmail,
    u.displayName=row.lastModifiedByUserDisplayName
MERGE (drive)-[r2:LAST_MODIFIED_BY]-(u)

WITH row WHERE row.createdByUserId IS NOT null
MERGE (drive:Drive {
    id: row.id
})
MERGE (u:User {
    id: row.createdByUserId
})
SET u.mail=row.createdByUserEmail,
    u.displayName=row.createdByUserDisplayName
MERGE (drive)-[r3:CREATED_BY]-(u)