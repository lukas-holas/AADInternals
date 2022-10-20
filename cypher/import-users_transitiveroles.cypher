// TODO: almost the same as import-personal_roles.cypher (param userId instead of personalId)
// TODO: same as import-users_roles.cypher
LOAD CSV WITH HEADERS FROM 'file:///users_transitiveroles.csv' AS row
MERGE (role:Role {
    id: row.id
})
SET role.deletedDateTime=datetime(row.deletedDateTime),
    role.displayName=row.displayName,
    role.description=row.description
MERGE (u:User {id: row.userId})
MERGE (u)-[r:HAS_ROLE]-(role)