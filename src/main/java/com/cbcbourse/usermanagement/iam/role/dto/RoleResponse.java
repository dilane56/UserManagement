package com.cbcbourse.usermanagement.iam.role.dto;

import java.util.Set;

public record RoleResponse(
        Long id,
        String code,
        String name,
        String description,
        boolean system,
        Set<String> permissions
) {
}
