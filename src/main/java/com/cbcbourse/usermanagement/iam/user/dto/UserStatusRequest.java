package com.cbcbourse.usermanagement.iam.user.dto;

import jakarta.validation.constraints.NotNull;

public record UserStatusRequest(
        @NotNull(message = "Le statut est obligatoire")
        Boolean enabled
) {
}
