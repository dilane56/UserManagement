package com.cbcbourse.usermanagement.iam.role.dto;

import jakarta.validation.constraints.NotNull;

import java.util.Set;

/** Remplace l'ensemble des permissions d'un rôle (un ensemble vide retire tout). */
public record RolePermissionsRequest(
        @NotNull(message = "La liste des permissions est obligatoire")
        Set<String> permissions
) {
}
