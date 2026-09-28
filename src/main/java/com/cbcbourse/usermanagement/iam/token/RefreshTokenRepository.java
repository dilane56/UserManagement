package com.cbcbourse.usermanagement.iam.token;

import com.cbcbourse.usermanagement.iam.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.time.Instant;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    @Modifying
    @Query("update RefreshToken t set t.revokedAt = :now where t.user = :user and t.revokedAt is null")
    int revokeAllByUser(User user, Instant now);

    @Modifying
    @Query("delete from RefreshToken t where t.user = :user")
    void deleteAllByUser(User user);

    @Modifying
    @Query("delete from RefreshToken t where t.expiresAt < :before or t.revokedAt < :before")
    int deleteObsolete(Instant before);
}
