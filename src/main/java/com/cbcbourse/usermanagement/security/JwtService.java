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
     * Vérifie la signature, l'émetteur et l'expiration.
     *
     * @throws JwtException si le token est invalide
     */
    public Claims parse(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .requireIssuer(properties.getIssuer())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public long getAccessTokenTtlSeconds() {
        return properties.getAccessTokenTtl().toSeconds();
    }
}
