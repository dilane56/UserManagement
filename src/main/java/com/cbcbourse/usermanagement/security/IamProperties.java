package com.cbcbourse.usermanagement.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/** Configuration du module IAM (préfixe {@code iam.*} dans application.yml). */
@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "iam")
public class IamProperties {

    private final Jwt jwt = new Jwt();
    private final Cors cors = new Cors();
    private final Security security = new Security();
    private final Registration registration = new Registration();
    private final Bootstrap bootstrap = new Bootstrap();

    @Getter
    @Setter
    public static class Jwt {
        /** Clé HMAC encodée en Base64 (au moins 256 bits / 32 octets). */
        @NotBlank
        private String secret;
        private String issuer = "user-management";
        private Duration accessTokenTtl = Duration.ofMinutes(15);
        private Duration refreshTokenTtl = Duration.ofDays(7);
    }

    @Getter
    @Setter
    public static class Cors {
        private List<String> allowedOrigins = new ArrayList<>(List.of("http://localhost:4200"));
        private List<String> allowedMethods = new ArrayList<>(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        private List<String> allowedHeaders = new ArrayList<>(List.of("*"));
        private boolean allowCredentials = true;
    }

    @Getter
    @Setter
    public static class Security {
        /** Chemins publics supplémentaires (ex : endpoints publics d'un futur module). */
        private List<String> publicPaths = new ArrayList<>();
    }

    @Getter
    @Setter
    public static class Registration {
        /** Active l'inscription libre via POST /api/auth/register. */
        private boolean enabled = false;
        /** Rôle attribué aux comptes créés sans rôle explicite. */
        private String defaultRole = "USER";
    }

    @Getter
    @Setter
    public static class Bootstrap {
        private boolean enabled = true;
        /** Rôle qui reçoit automatiquement toutes les permissions et ne peut pas être modifié ni supprimé. */
        private String superAdminRole = "ADMIN";
        private List<RoleSeed> roles = new ArrayList<>();
        private AdminSeed admin = new AdminSeed();
    }

    @Getter
    @Setter
    public static class RoleSeed {
        private String code;
        private String name;
        private String description;
        /** Permissions attribuées à la création du rôle uniquement (modifiables ensuite via l'API). */
        private List<String> permissions = new ArrayList<>();
    }

    @Getter
    @Setter
    public static class AdminSeed {
        private String email;
        /** Si vide, un mot de passe aléatoire est généré et affiché une seule fois dans les logs. */
        private String password;
        private String nom = "Administrateur";
        private String prenom = "Système";
    }
}
