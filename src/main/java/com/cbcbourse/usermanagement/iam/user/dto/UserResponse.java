package com.cbcbourse.usermanagement.iam.user.dto;

import java.time.Instant;
import java.util.Set;

public record UserResponse(
        Long id,
        String nom,
        String prenom,
        String email,
        boolean enabled,
        Set<String> roles,
        Instant lastLoginAt,
        Instant createdAt
) {
}
