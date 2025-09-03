LOAD CSV WITH HEADERS FROM 'file:///personal_people_groups.csv' AS row
MERGE (g:Group {
    id: row.id
})
SET g.displayName=row.displayName,
    g.givenName=row.givenName,
    g.surname=row.surname,
    g.birthday=row.birthday,
    g.jobTitle=row.jobTitle,
    g.companyName=row.companyName,
    g.department=row.department,
    g.profession=row.profession,
    g.imAddress=row.imAddress,
    g.phone=row.phone,
    g.officeLocation=row.officeLocation,
    g.userPrincipalName=row.userPrincipalName,
    g.class=row.class,
    g.subclass=row.subclass
MERGE (u2:User {id: row.personalId})
MERGE (u2)-[r:RELATED_TO]-(g)
SET r.relevanceScore=toFloat(row.relevanceScore),
    r.scoredEmailAddresses=row.scoredEmailAddresses,
    r.personNotes=row.personNotes,
    r.isFavorite=toBoolean(row.isFavorite)