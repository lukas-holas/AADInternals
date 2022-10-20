LOAD CSV WITH HEADERS FROM 'file:///group_drivefolders.csv' AS row
MERGE (folder:Folder {
    id: row.id
})
SET folder.createdDateTime=datetime(row.createdDateTime),
    folder.lastModifiedDateTime=datetime(row.lastModifiedDateTime),
    folder.webUrl=row.webUrl,
    folder.name=row.name,
    folder.size=toInteger(row.size),
    folder.childFolderCount=row.folder
MERGE (g:Group {id: row.groupId})
MERGE (g)-[r1:HAS_FOLDER]-(folder)
MERGE (d:Drive {id: row.parentReferenceDriveId})
MERGE (folder)-[r2:IS_IN]-(d)
MERGE (parentFolder:Folder {id: row.parentReferenceId})
SET folder.path=row.parentReferencePath
MERGE (folder)-[r3:IS_IN]-(parentFolder)
 
WITH row WHERE row.createdByUser IS NOT null
MERGE (folder:Folder {
    id: row.id
})
MERGE (u1:User {id: row.createdByUser})
MERGE (folder)-[r4:CREATED_BY]-(u1)
 
WITH row WHERE row.lastModifiedByUser IS NOT null
MERGE (folder:Folder {
    id: row.id
})
MERGE (u2:User {id: row.lastModifiedByUser})
MERGE (folder)-[r6:LAST_MODIFIED_BY]-(u2)
 
WITH row WHERE row.createdByApplication IS NOT null
MERGE (folder:Folder {
    id: row.id
})
MERGE (a1:Application {id: row.createdByApplication})
MERGE (folder)-[r5:CREATED_BY]-(a1)
 
WITH row WHERE row.lastModifiedByApplication IS NOT null
MERGE (folder:Folder {
    id: row.id
})
MERGE (a2:Application {id: row.lastModifiedByApplication})
MERGE (folder)-[r7:LAST_MODIFIED_BY]-(a2)