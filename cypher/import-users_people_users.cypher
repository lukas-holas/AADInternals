// TODO: almost the same as import-personal_people_users.cypher (param userId instead of personalId)
LOAD CSV WITH HEADERS FROM 'file:///users_people_users.csv' AS row
MERGE (u:User {
    id: row.id
})
SET u.displayName=row.displayName,
    u.givenName=row.givenName,
    u.surname=row.surname,
    u.birthday=row.birthday,
    u.jobTitle=row.jobTitle,
    u.companyName=row.companyName,
    u.department=row.department,
    u.profession=row.profession,
    u.imAddress=row.imAddress,
    u.phone=row.phone,
    u.officeLocation=row.officeLocation,
    u.userPrincipalName=row.userPrincipalName,
    u.class=row.class,
    u.subclass=row.subclass
MERGE (u2:User {id: row.userId})
MERGE (u2)-[r:RELATED_TO]-(u)
SET r.relevanceScore=toFloat(row.relevanceScore),
    r.scoredEmailAddresses=row.scoredEmailAddresses,
    r.personNotes=row.personNotes,
    r.isFavorite=toBoolean(row.isFavorite)