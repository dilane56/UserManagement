package com.cbcbourse.usermanagement.iam.token;

import com.cbcbourse.usermanagement.common.exception.ApiException;
import com.cbcbourse.usermanagement.iam.user.User;
import com.cbcbourse.usermanagement.security.IamProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class RefreshTokenService {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final RefreshTokenRepository refreshTokenRepository;
    private final IamProperties iamProperties;

    /** Crée un refresh token pour l'utilisateur et renvoie sa valeur brute (jamais stockée). */
    public String issue(User user) {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        String rawToken = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

        RefreshToken token = new RefreshToken();
        token.setUser(user);
        token.setTokenHash(hash(rawToken));
        token.setExpiresAt(Instant.now().plus(iamProperties.getJwt().getRefreshTokenTtl()));
        refreshTokenRepository.save(token);
        return rawToken;
    }

    /**
     * Valide et révoque le token présenté (rotation). Si un token déjà révoqué est réutilisé,
     * c'est le signe d'un vol : toutes les sessions de l'utilisateur sont révoquées.
     */
    @Transactional(noRollbackFor = ApiException.class)
    public User consume(String rawToken) {
        RefreshToken token = refreshTokenRepository.findByTokenHash(hash(rawToken))
                .orElseThrow(RefreshTokenService::invalidToken);
        Instant now = Instant.now();
        if (token.getRevokedAt() != null) {
            log.warn("Réutilisation d'un refresh token révoqué (utilisateur id={}) : révocation de toutes ses sessions",
                    token.getUser().getId());
            refreshTokenRepository.revokeAllByUser(token.getUser(), now);
            throw invalidToken();
        }
        if (!token.isActive(now)) {
            throw invalidToken();
        }
        token.setRevokedAt(now);
        return token.getUser();
    }

    public void revoke(String rawToken) {
        refreshTokenRepository.findByTokenHash(hash(rawToken))
                .filter(t -> t.getRevokedAt() == null)
                .ifPresent(t -> t.setRevokedAt(Instant.now()));
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void revokeAll(User user) {
        refreshTokenRepository.revokeAllByUser(user, Instant.now());
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void deleteAll(User user) {
        refreshTokenRepository.deleteAllByUser(user);
    }

    /** Purge quotidienne des tokens expirés ou révoqués depuis plus d'un jour. */
    @Scheduled(cron = "${iam.jwt.refresh-token-cleanup-cron:0 0 3 * * *}")
    public void purgeObsoleteTokens() {
        int deleted = refreshTokenRepository.deleteObsolete(Instant.now().minusSeconds(86_400));
        if (deleted > 0) {
            log.info("{} refresh tokens obsolètes supprimés", deleted);
        }
    }

    private static ApiException invalidToken() {
        return new ApiException(HttpStatus.UNAUTHORIZED, "Refresh token invalide ou expiré");
    }

    private static String hash(String rawToken) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 indisponible", e);
        }
    }
}
