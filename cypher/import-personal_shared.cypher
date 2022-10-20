LOAD CSV WITH HEADERS FROM 'file:///personal_shared.csv' AS row
MERGE (s:Shared {
    id: row.id
})
SET s.sharedDateTime=datetime(row.sharedDateTime),
    s.title=row.title,
    s.containerWebUrl=row.containerWebUrl,
    s.containerDisplayName=row.containerDisplayName,
    s.containerType=row.containerType,
    s.resourceWebUrl=row.resourceWebUrl,
    s.resourceId=row.resourceId,
    s.resourceType=row.resourceType
MERGE (u:User {id: row.personalId})
MERGE (u)-[r:HAS_SHARED]-(s)