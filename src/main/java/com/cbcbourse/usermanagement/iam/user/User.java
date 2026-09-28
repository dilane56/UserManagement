package com.cbcbourse.usermanagement.iam.user;

import com.cbcbourse.usermanagement.common.model.BaseEntity;
import com.cbcbourse.usermanagement.iam.role.Role;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.BatchSize;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "iam_users")
public class User extends BaseEntity {

    @Column(nullable = false, length = 100)
    private String nom;

    @Column(length = 100)
    private String prenom;

    /** Toujours stocké en minuscules (voir UserService). */
    @Column(nullable = false, unique = true, length = 150)
    private String email;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(name = "last_login_at")
    private Instant lastLoginAt;

    @ManyToMany
    @BatchSize(size = 50)
    @JoinTable(name = "iam_user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles = new HashSet<>();

    public boolean hasRole(String roleCode) {
        return roles.stream().anyMatch(r -> r.getCode().equals(roleCode));
    }
}
