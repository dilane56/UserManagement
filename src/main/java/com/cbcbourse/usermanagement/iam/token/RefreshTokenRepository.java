package com.cbcbourse.usermanagement.iam.token;

import com.cbcbourse.usermanagement.iam.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.time.Instant;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    /** Recherche un token par son empreinte SHA-256 (la valeur brute n'est jamais stockée). */
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    /** Révoque en une requête tous les tokens encore actifs de l'utilisateur ; renvoie le nombre de tokens révoqués. */
    @Modifying
    @Query("update RefreshToken t set t.revokedAt = :now where t.user = :user and t.revokedAt is null")
    int revokeAllByUser(User user, Instant now);

    /** Supprime tous les tokens de l'utilisateur (nécessaire avant de supprimer son compte, à cause de la clé étrangère). */
    @Modifying
    @Query("delete from RefreshToken t where t.user = :user")
    void deleteAllByUser(User user);

    /** Supprime les tokens expirés ou révoqués avant la date donnée ; renvoie le nombre de lignes supprimées. */
    @Modifying
    @Query("delete from RefreshToken t where t.expiresAt < :before or t.revokedAt < :before")
    int deleteObsolete(Instant before);
}
