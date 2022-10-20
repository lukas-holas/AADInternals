#!/bin/bash
# Script to import CSV files extracted from AADInternals into Neo4j
# Copyright (C) 2022 Nicolas Vincent
# Permission to copy and modify is granted under the GPLv3 license
# Last revised 03/07/2022

function die {
    printf "Script failed: %s\n\n" "$1"
    exit 1
}

programname=$0
function usage {
    echo ""
    echo "Import CSV files extracted from AADInternals into Neo4j"
    echo ""
    echo "usage: $programname --username string --password string [--directory cypher/ --setup-database --clear-database]"
    echo ""
    echo "  --username,-u string    username of the Neo4j database"
    echo "  --password,-p string    password of the Neo4j database"
    echo "  --directory,-d string   (Optional) directory with the .cypher scripts"
    echo "  --import                (Optional) import all the files into the database"
    echo "  --setup-database        (Optional) create the indexes and constraints"
    echo "  --clear-database        (Optional) clear the database content, indexes and constraints"
    echo ""
}

username=
password=
directory=${directory:-cypher/}
import=
setupdatabase=
cleardatabase=

while [ $# -gt 0 ]; do
    case $1 in
        -h|--help) usage; exit 0 ;;
        -u|--username) username="$2"; shift; shift ;;
        -p|--password) password="$2"; shift; shift ;;
        -d| --directory) directory="$2"; shift; shift ;;
        --import) import=1; shift ;;
        --setup-database) setupdatabase=1; shift ;;
        --clear-database) cleardatabase=1; shift ;;
        *) usage; die "Unknown parameter passed: $1"; shift; shift ;;
    esac
    # if [[ $1 == "--option-"* ]]; then
    #     param="${1/--/}"
    #     declare "$param"="$2"
    # fi
    # shift
done

if [[ -z $username ]]; then
    usage
    die "Missing parameter --username"
elif [[ -z $password ]]; then
    usage
    die "Missing parameter --password"
fi

if [[ $setupdatabase -eq 1 ]]; then
    echo "Creating the constraints and indexes"
    cypher-shell -u "$username" -p "$password" < "${directory}create-indexes.cypher"
    cypher-shell -u "$username" -p "$password" < "${directory}create-constraints.cypher"
fi

if [[ $cleardatabase -eq 1 ]]; then
    echo "Clearing the database"
    cypher-shell -u "$username" -p "$password" < "${directory}clear-database.cypher"
    # done by clear-database.cypher
    # echo "Dropping the constraints and indexes"
    # cypher-shell -u "$username" -p "$password" < "${directory}drop-indexes.cypher"
    # cypher-shell -u "$username" -p "$password" < "${directory}drop-constraints.cypher"
fi

if [[ $import -eq 1 ]]; then
    # -P "filename => 'file:///ips-ad-nmap.csv'"
    echo "Importing current_user"
    cypher-shell -u "$username" -p "$password" < "${directory}import-current_user.cypher"
    echo "Importing personal_drivefiles"
    cypher-shell -u "$username" -p "$password" < "${directory}import-personal_drivefiles.cypher"
    echo "Importing personal_drivefolders"
    cypher-shell -u "$username" -p "$password" < "${directory}import-personal_drivefolders.cypher"
    echo "Importing personal_groups"
    cypher-shell -u "$username" -p "$password" < "${directory}import-personal_groups.cypher"
    echo "Importing personal_joinedteams"
    cypher-shell -u "$username" -p "$password" < "${directory}import-personal_joinedteams.cypher"
    echo "Importing personal_people_users"
    cypher-shell -u "$username" -p "$password" < "${directory}import-personal_people_users.cypher"
    echo "Importing personal_people_groups"
    cypher-shell -u "$username" -p "$password" < "${directory}import-personal_people_groups.cypher"
    echo "Importing personal_roles"
    cypher-shell -u "$username" -p "$password" < "${directory}import-personal_roles.cypher"
    echo "Importing personal_rootfolder"
    cypher-shell -u "$username" -p "$password" < "${directory}import-personal_rootfolder.cypher"
    echo "Importing personal_shared"
    cypher-shell -u "$username" -p "$password" < "${directory}import-personal_shared.cypher"
    echo "Importing personal_sharedinsights"
    cypher-shell -u "$username" -p "$password" < "${directory}import-personal_sharedinsights.cypher"
    echo ""
    echo "Importing groups"
    cypher-shell -u "$username" -p "$password" < "${directory}import-groups.cypher"
    echo "Importing group_drivefiles"
    cypher-shell -u "$username" -p "$password" < "${directory}import-group_drivefiles.cypher"
    echo "Importing group_drivefolders"
    cypher-shell -u "$username" -p "$password" < "${directory}import-group_drivefolders.cypher"
    echo "Importing group_drives"
    cypher-shell -u "$username" -p "$password" < "${directory}import-group_drives.cypher"
    echo "Importing group_members"
    cypher-shell -u "$username" -p "$password" < "${directory}import-group_members.cypher"
    echo "Importing group_owners"
    cypher-shell -u "$username" -p "$password" < "${directory}import-group_owners.cypher"
    echo "Importing group_rootfolder"
    cypher-shell -u "$username" -p "$password" < "${directory}import-group_rootfolder.cypher"
    echo "Importing role_members"
    cypher-shell -u "$username" -p "$password" < "${directory}import-role_members.cypher"
    echo "Importing team"
    cypher-shell -u "$username" -p "$password" < "${directory}import-team.cypher"
    echo "Importing team_members"
    cypher-shell -u "$username" -p "$password" < "${directory}import-team_members.cypher"
    echo ""
    echo "Importing users"
    cypher-shell -u "$username" -p "$password" < "${directory}import-users.cypher"
    echo "Importing users_groups"
    cypher-shell -u "$username" -p "$password" < "${directory}import-users_groups.cypher"
    echo "Importing users_informations"
    cypher-shell -u "$username" -p "$password" < "${directory}import-users_informations.cypher"
    echo "Importing users_joinedteams"
    cypher-shell -u "$username" -p "$password" < "${directory}import-users_joinedteams.cypher"
    echo "Importing users_people_users"
    cypher-shell -u "$username" -p "$password" < "${directory}import-users_people_users.cypher"
    echo "Importing users_people_groups"
    cypher-shell -u "$username" -p "$password" < "${directory}import-users_people_groups.cypher"
    echo "Importing users_roles"
    cypher-shell -u "$username" -p "$password" < "${directory}import-users_roles.cypher"
    echo "Importing users_shared"
    cypher-shell -u "$username" -p "$password" < "${directory}import-users_shared.cypher"
    echo "Importing users_sharedinsights"
    cypher-shell -u "$username" -p "$password" < "${directory}import-users_sharedinsights.cypher"
    echo "Importing users_transitivegroups"
    cypher-shell -u "$username" -p "$password" < "${directory}import-users_transitivegroups.cypher"
    echo "Importing users_transitiveroles"
    cypher-shell -u "$username" -p "$password" < "${directory}import-users_transitiveroles.cypher"
    echo ""
    echo "Importing audit_log"
    cypher-shell -u "$username" -p "$password" < "${directory}import-audit_log.cypher"
    cypher-shell -u "$username" -p "$password" < "${directory}import-audit_log_target_resources.cypher"
    cypher-shell -u "$username" -p "$password" < "${directory}import-audit_log_target_resources_modified_properties.cypher"
    echo "Importing delegated_permissions_grant"
    cypher-shell -u "$username" -p "$password" < "${directory}import-delegated_permissions_grant.cypher"
    echo "Importing service_principals"
    cypher-shell -u "$username" -p "$password" < "${directory}import-service_principals.cypher"
    cypher-shell -u "$username" -p "$password" < "${directory}import-permission_scopes.cypher"
    cypher-shell -u "$username" -p "$password" < "${directory}import-app_roles.cypher"
    cypher-shell -u "$username" -p "$password" < "${directory}import-app_roles_assigned_to.cypher"
fi