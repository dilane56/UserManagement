package com.cbcbourse.usermanagement.iam.role.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.Set;

public record RoleCreateRequest(
        @NotBlank(message = "Le code est obligatoire")
        @Pattern(regexp = "^[A-Za-z][A-Za-z0-9_]{1,49}$",
                message = "Le code doit contenir 2 à 50 caractères (lettres, chiffres, _)")
        String code,

        @NotBlank(message = "Le nom est obligatoire")
        @Size(max = 100)
        String name,

        @Size(max = 255)
        String description,

        Set<String> permissions
) {
}
