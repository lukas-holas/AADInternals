LOAD CSV WITH HEADERS FROM 'file:///group_owners.csv' AS row
MERGE (u:User {
    id: row.id
})
SET u.businessPhones=row.businessPhones, // "" when empty, not null
    u.displayName=row.displayName,
    u.givenName=row.givenName,
    u.surname=row.surname,
    u.jobTitle=row.jobTitle,
    u.mail=row.mail,
    u.mobilePhone=row.mobilePhone,
    u.officeLocation=row.officeLocation,
    u.userPrincipalName=row.userPrincipalName,
    u.onPremisesDistinguishedName=row.onPremisesDistinguishedName,
    u.onPremisesImmutableId=row.onPremisesImmutableId,
    u.onPremisesLastSyncDateTime=datetime(row.onPremisesLastSyncDateTime),
    u.onPremisesSamAccountName=row.onPremisesSamAccountName,
    u.refreshTokensValidFromDateTime=datetime(row.refreshTokensValidFromDateTime),
    u.signInSessionsValidFromDateTime=datetime(row.signInSessionsValidFromDateTime),
    u.usageLocation=row.usageLocation, // "" when empty, not null
    u.proxyAddresses=row.proxyAddresses, // "" when empty, not null
    u.provisionedPlans=row.provisionedPlans
MERGE (g:Group {id: row.groupId})
MERGE (u)-[r:OWNS]-(g)