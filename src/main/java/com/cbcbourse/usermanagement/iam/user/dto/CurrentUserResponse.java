package com.cbcbourse.usermanagement.iam.user.dto;

import java.util.Set;

/** Utilisateur connecté, avec ses permissions effectives (utile au front pour afficher/masquer). */
public record CurrentUserResponse(
        Long id,
        String nom,
        String prenom,
        String email,
        Set<String> roles,
        Set<String> permissions
) {
}
