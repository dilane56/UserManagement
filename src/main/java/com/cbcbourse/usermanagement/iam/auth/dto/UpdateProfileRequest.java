package com.cbcbourse.usermanagement.iam.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UpdateProfileRequest(
        @NotBlank(message = "Le nom est obligatoire")
        @Size(max = 100)
        String nom,

        @NotBlank(message = "Le prénom est obligatoire")
        @Size(max = 100)
        String prenom
) {
}
