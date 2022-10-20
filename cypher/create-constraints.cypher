CREATE CONSTRAINT userUniqueConstraint FOR (u:User) REQUIRE u.id IS UNIQUE;
CREATE CONSTRAINT applicationUniqueConstraint FOR (a:Application) REQUIRE a.id IS UNIQUE;
CREATE CONSTRAINT groupUniqueConstraint FOR (g:Group) REQUIRE g.id IS UNIQUE;
CREATE CONSTRAINT roleUniqueConstraint FOR (r:Role) REQUIRE r.id IS UNIQUE;
CREATE CONSTRAINT teamUniqueConstraint FOR (t:Team) REQUIRE t.id IS UNIQUE;
CREATE CONSTRAINT teamMemberUniqueConstraint FOR (t:TeamMember) REQUIRE t.id IS UNIQUE;
CREATE CONSTRAINT driveUniqueConstraint FOR (d:Drive) REQUIRE d.id IS UNIQUE;
CREATE CONSTRAINT fileUniqueConstraint FOR (f:File) REQUIRE f.id IS UNIQUE;
CREATE CONSTRAINT folderUniqueConstraint FOR (f:Folder) REQUIRE f.id IS UNIQUE;
CREATE CONSTRAINT sharedUniqueConstraint FOR (s:Shared) REQUIRE s.id IS UNIQUE;


