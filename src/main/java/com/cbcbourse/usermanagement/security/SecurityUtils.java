package com.cbcbourse.usermanagement.security;

import com.cbcbourse.usermanagement.common.exception.ApiException;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

/** Accès à l'utilisateur connecté depuis n'importe quelle couche (services des modules métier inclus). */
public final class SecurityUtils {

    private SecurityUtils() {
    }

    public static Optional<UserPrincipal> currentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof UserPrincipal principal) {
            return Optional.of(principal);
        }
        return Optional.empty();
    }

    public static UserPrincipal requireCurrentUser() {
        return currentUser().orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "Authentification requise"));
    }

    public static Long requireCurrentUserId() {
        return requireCurrentUser().getId();
    }

    public static boolean hasPermission(String permission) {
        return currentUser().map(u -> u.getPermissions().contains(permission)).orElse(false);
    }
}
