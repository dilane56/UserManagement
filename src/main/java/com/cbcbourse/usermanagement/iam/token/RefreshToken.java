package com.cbcbourse.usermanagement.iam.token;

import com.cbcbourse.usermanagement.common.model.BaseEntity;
import com.cbcbourse.usermanagement.iam.user.User;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/** Refresh token opaque. Seul son empreinte SHA-256 est stockée. */
@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "iam_refresh_tokens", indexes = @Index(name = "idx_refresh_token_user", columnList = "user_id"))
public class RefreshToken extends BaseEntity {

    @Column(name = "token_hash", nullable = false, unique = true, length = 64)
    private String tokenHash;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    public boolean isActive(Instant now) {
        return revokedAt == null && expiresAt.isAfter(now);
    }
}
