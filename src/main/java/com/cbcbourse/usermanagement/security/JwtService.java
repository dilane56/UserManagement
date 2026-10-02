package com.cbcbourse.usermanagement.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;

/** Émission et validation des access tokens JWT (HMAC-SHA). */
@Service
public class JwtService {

    public static final String CLAIM_USER_ID = "uid";
    public static final String CLAIM_ROLES = "roles";
    public static final String CLAIM_PERMISSIONS = "permissions";

    private final IamProperties.Jwt properties;
    private final SecretKey signingKey;

    /**
     * Prépare la clé de signature HMAC à partir de iam.jwt.secret (JWT_SECRET).
     * L'application refuse de démarrer si la clé n'est pas du Base64 valide ou fait moins de 256 bits :
     * mieux vaut une erreur au démarrage qu'une clé faible en production.
     */
    public JwtService(IamProperties iamProperties) {
        this.properties = iamProperties.getJwt();
        byte[] keyBytes;
        try {
            keyBytes = Decoders.BASE64.decode(properties.getSecret());
        } catch (RuntimeException e) {
            throw new IllegalStateException("iam.jwt.secret (JWT_SECRET) doit être une chaîne Base64 valide", e);
        }
        if (keyBytes.length < 32) {
            throw new IllegalStateException("iam.jwt.secret (JWT_SECRET) doit faire au moins 256 bits (32 octets)");
        }
        this.signingKey = Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Génère un access token signé pour l'utilisateur.
     * Contenu : sujet = email, {@code uid} = identifiant, {@code roles} et {@code permissions} (informatifs pour le front),
     * émetteur et date d'expiration (iam.jwt.access-token-ttl).
     * Côté serveur, les droits ne sont pas lus dans le token mais rechargés en base à chaque requête.
     */
    public String generateAccessToken(UserPrincipal user) {
        Instant now = Instant.now();
        return Jwts.builder()
                .issuer(properties.getIssuer())
                .subject(user.getEmail())
                .claim(CLAIM_USER_ID, user.getId())
                .claim(CLAIM_ROLES, user.getRoles())
                .claim(CLAIM_PERMISSIONS, user.getPermissions())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(properties.getAccessTokenTtl())))
                .signWith(signingKey)
                .compact();
    }

    /**
     * Vérifie la signature, l'émetteur et l'expiration, puis renvoie le contenu (claims) du token.
     *
     * @throws io.jsonwebtoken.ExpiredJwtException si le token est expiré
     * @throws JwtException                        si le token est invalide (signature, format, émetteur)
     */
    public Claims parse(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .requireIssuer(properties.getIssuer())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /** Durée de vie d'un access token en secondes, renvoyée au client dans {@code expiresIn}. */
    public long getAccessTokenTtlSeconds() {
        return properties.getAccessTokenTtl().toSeconds();
    }
}
