// TODO: same as import-personal_rootfolder.cypher
LOAD CSV WITH HEADERS FROM 'file:///group_rootfolder.csv' AS row
MERGE (f:Folder {
    id: row.id
})
SET f.createdDateTime=datetime(row.createdDateTime),
    f.lastModifiedDateTime=datetime(row.lastModifiedDateTime),
    f.webUrl=row.webUrl,
    f.name=row.name,
    f.size=toInteger(row.size),
    f.childFolderCount=row.folder
MERGE (d:Drive {id: row.parentReferenceDriveId})
MERGE (f)-[r:IS_IN]-(d)