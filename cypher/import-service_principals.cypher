LOAD CSV WITH HEADERS FROM 'file:///service_principals.csv' AS row
MERGE (s:ServicePrincipal {
    id: row.id
})
SET s.deletedDateTime=datetime(row.deletedDateTime),
    s.accountEnabled=toBoolean(row.accountEnabled),
    s.alternativeNames=row.alternativeNames, // "" when empty, not null
    s.appDisplayName=row.appDisplayName,
    s.appDescription=row.appDescription,
    // s.appId=row.appId,
    s.applicationTemplateId=row.applicationTemplateId,
    // s.appOwnerOrganizationId=row.appOwnerOrganizationId,
    s.appRoleAssignmentRequired=toBoolean(row.appRoleAssignmentRequired),
    s.createdDateTime=datetime(row.createdDateTime),
    s.description=row.description,
    s.disabledByMicrosoftStatus=row.disabledByMicrosoftStatus,
    s.displayName=row.displayName,
    s.homepage=row.homepage,
    s.loginUrl=row.loginUrl,
    s.logoutUrl=row.logoutUrl,
    s.notes=row.notes,
    s.notificationEmailAddresses=row.notificationEmailAddresses, // "" when empty, not null
    s.preferredSingleSignOnMode=row.preferredSingleSignOnMode,
    s.preferredTokenSigningKeyThumbprint=row.preferredTokenSigningKeyThumbprint,
    s.replyUrls=row.replyUrls, // "" when empty, not null
    s.servicePrincipalNames=row.servicePrincipalNames,
    s.servicePrincipalType=row.servicePrincipalType,
    s.signInAudience=row.signInAudience,
    s.tags=row.tags, // "" when empty, not null
    s.tokenEncryptionKeyId=row.tokenEncryptionKeyId,
    s.samlSingleSignOnSettings=row.samlSingleSignOnSettings,
    s.verifiedPublisherDisplayName=row.verifiedPublisherDisplayName,
    s.verifiedPublisherId=row.verifiedPublisherId,
    s.verifiedPublisherAddedDateTime=datetime(row.verifiedPublisherAddedDateTime),
    s.logoUrl=row.logoUrl,
    s.marketingUrl=row.marketingUrl,
    s.privacyStatementUrl=row.privacyStatementUrl,
    s.supportUrl=row.supportUrl,
    s.termsOfServiceUrl=row.termsOfServiceUrl
MERGE (a:Application {id: row.appId})
MERGE (s)-[r1:ASSOCIATED_APPLICATION]-(a)

WITH row WHERE row.appOwnerOrganizationId IS NOT null
MERGE (a:Application {id: row.appId})
MERGE (t:Tenant {id: row.appOwnerOrganizationId})
MERGE (t)-[r2:REGISTERED_APPLICATION]-(a)