LOAD CSV WITH HEADERS FROM 'file:///personal_roles.csv' AS row
MERGE (role:Role {
    id: row.id
})
SET role.deletedDateTime=datetime(row.deletedDateTime),
    role.displayName=row.displayName,
    role.description=row.description
MERGE (u:User {id: row.personalId})
MERGE (u)-[r:HAS_ROLE]-(role)