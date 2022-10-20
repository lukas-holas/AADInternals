LOAD CSV WITH HEADERS FROM 'file:///personal_drivefiles.csv' AS row
MERGE (file:File {
    id: row.id
})
SET file.createdDateTime=datetime(row.createdDateTime),
    file.lastModifiedDateTime=datetime(row.lastModifiedDateTime),
    file.downloadUrl=row.microsoftGraphDownloadUrl,
    file.webUrl=row.webUrl,
    file.name=row.name,
    file.size=toInteger(row.size),
    file.sharedScope=row.sharedScope
MERGE (u:User {id: row.personalId})
MERGE (u)-[r1:HAS_FILE]-(file)
MERGE (d:Drive {id: row.parentReferenceDriveId})
MERGE (file)-[r2:IS_IN]-(d)
MERGE (folder:Folder {id: row.parentReferenceId})
SET folder.path=row.parentReferencePath
MERGE (file)-[r3:IS_IN]-(folder)

WITH row WHERE row.createdByUser IS NOT null
MERGE (file:File {
    id: row.id
})
MERGE (u1:User {id: row.createdByUser})
MERGE (file)-[r4:CREATED_BY]-(u1)

WITH row WHERE row.lastModifiedByUser IS NOT null
MERGE (file:File {
    id: row.id
})
MERGE (u2:User {id: row.lastModifiedByUser})
MERGE (file)-[r6:LAST_MODIFIED_BY]-(u2)

WITH row WHERE row.createdByApplication IS NOT null
MERGE (file:File {
    id: row.id
})
MERGE (a1:Application {id: row.createdByApplication})
MERGE (file)-[r5:CREATED_BY]-(a1)

WITH row WHERE row.lastModifiedByApplication IS NOT null
MERGE (file:File {
    id: row.id
})
MERGE (a2:Application {id: row.lastModifiedByApplication})
MERGE (file)-[r7:LAST_MODIFIED_BY]-(a2)