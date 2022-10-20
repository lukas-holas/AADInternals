// TODO: almost the same as import-personal_roles.cypher (param userId instead of personalId)
LOAD CSV WITH HEADERS FROM 'file:///users_roles.csv' AS row
MERGE (role:Role {
    id: row.id
})
SET role.deletedDateTime=datetime(row.deletedDateTime),
    role.displayName=row.displayName,
    role.description=row.description
MERGE (u:User {id: row.userId})
MERGE (u)-[r:HAS_ROLE]-(role)