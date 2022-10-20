// TODO: same as import-current_user.cypher
LOAD CSV WITH HEADERS FROM 'file:///users_informations.csv' AS row
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
    u.usageLocation=row.usageLocation,
    u.proxyAddresses=row.proxyAddresses,
    u.provisionedPlans=row.provisionedPlans