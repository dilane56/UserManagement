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

    /**
     * Renvoie l'utilisateur authentifié sur la requête en cours, ou un {@code Optional} vide
     * si la requête est anonyme (route publique, tâche planifiée, démarrage de l'application...).
     */
    public static Optional<UserPrincipal> currentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof UserPrincipal principal) {
            return Optional.of(principal);
        }
        return Optional.empty();
    }

    /**
     * Renvoie l'utilisateur authentifié, à utiliser lorsque l'opération exige une connexion.
     *
     * @throws ApiException 401 si aucun utilisateur n'est authentifié
     */
    public static UserPrincipal requireCurrentUser() {
        return currentUser().orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "Authentification requise"));
    }

    /**
     * Identifiant de l'utilisateur authentifié (ex : pour rattacher une donnée métier à son propriétaire).
     *
     * @throws ApiException 401 si aucun utilisateur n'est authentifié
     */
    public static Long requireCurrentUserId() {
        return requireCurrentUser().getId();
    }

    /**
     * Vérifie dans le code si l'utilisateur connecté possède une permission, pour les cas où
     * {@code @PreAuthorize} ne suffit pas (ex : afficher ou masquer des données selon les droits).
     * Renvoie {@code false} si personne n'est connecté.
     */
    public static boolean hasPermission(String permission) {
        return currentUser().map(u -> u.getPermissions().contains(permission)).orElse(false);
    }
}
