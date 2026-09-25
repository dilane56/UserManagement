package com.cbcbourse.usermanagement.iam.user.dto;

import jakarta.validation.constraints.NotEmpty;

import java.util.Set;

/** Remplace l'ensemble des rôles d'un utilisateur. */
public record UserRolesRequest(
        @NotEmpty(message = "Au moins un rôle est obligatoire")
        Set<String> roles
) {
}
