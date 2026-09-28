package com.cbcbourse.usermanagement.iam.auth.dto;

import com.cbcbourse.usermanagement.iam.user.dto.CurrentUserResponse;

public record AuthResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        long expiresIn,
        CurrentUserResponse user
) {
    public static AuthResponse bearer(String accessToken, String refreshToken, long expiresIn, CurrentUserResponse user) {
        return new AuthResponse(accessToken, refreshToken, "Bearer", expiresIn, user);
    }
}
