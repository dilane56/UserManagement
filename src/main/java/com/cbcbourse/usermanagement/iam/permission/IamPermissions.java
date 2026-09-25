package com.cbcbourse.usermanagement.iam.permission;

import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;

/** Permissions du module IAM. Les constantes sont utilisables dans {@code @PreAuthorize}. */
@Component
public class IamPermissions implements PermissionProvider {

    public static final String MODULE = "IAM";

    public static final String USER_READ = "USER_READ";
    public static final String USER_CREATE = "USER_CREATE";
    public static final String USER_UPDATE = "USER_UPDATE";
    public static final String USER_DELETE = "USER_DELETE";

    public static final String ROLE_READ = "ROLE_READ";
    public static final String ROLE_CREATE = "ROLE_CREATE";
    public static final String ROLE_UPDATE = "ROLE_UPDATE";
    public static final String ROLE_DELETE = "ROLE_DELETE";

    public static final String PERMISSION_READ = "PERMISSION_READ";

    @Override
    public Collection<PermissionDefinition> permissions() {
        return List.of(
                new PermissionDefinition(USER_READ, "Consulter les utilisateurs", MODULE),
                new PermissionDefinition(USER_CREATE, "Créer des utilisateurs", MODULE),
                new PermissionDefinition(USER_UPDATE, "Modifier les utilisateurs, leurs rôles et leur statut", MODULE),
                new PermissionDefinition(USER_DELETE, "Supprimer des utilisateurs", MODULE),
                new PermissionDefinition(ROLE_READ, "Consulter les rôles", MODULE),
                new PermissionDefinition(ROLE_CREATE, "Créer des rôles", MODULE),
                new PermissionDefinition(ROLE_UPDATE, "Modifier les rôles et leurs permissions", MODULE),
                new PermissionDefinition(ROLE_DELETE, "Supprimer des rôles", MODULE),
                new PermissionDefinition(PERMISSION_READ, "Consulter les permissions", MODULE)
        );
    }
}
