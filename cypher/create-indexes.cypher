CREATE INDEX userIndexDisplayName FOR (u:User) ON (u.displayName);
CREATE INDEX userIndexMail FOR (u:User) ON (u.mail);
CREATE INDEX userIndexUserPrincipalName FOR (u:User) ON (u.userPrincipalName);

CREATE INDEX groupIndexDisplayName FOR (g:Group) ON (g.displayName);
CREATE INDEX groupIndexVisibility FOR (g:Group) ON (g.visibility);

CREATE INDEX teamIndexDisplayName FOR (t:Team) ON (t.displayName);
CREATE INDEX teamIndexVisibility FOR (t:Team) ON (t.visibility);

CREATE INDEX teamMemberIndexDisplayName FOR (t:TeamMember) ON (t.displayName);
CREATE INDEX teamMemberIndexRoles FOR (t:TeamMember) ON (t.roles);

CREATE INDEX roleIndexDisplayName FOR (r:Role) ON (r.displayName);

CREATE INDEX fileIndexName FOR (f:File) ON (f.name);
CREATE INDEX folderIndexName FOR (f:Folder) ON (f.name);

CREATE INDEX sharedIndexTitle FOR (s:Shared) ON (s.title);

