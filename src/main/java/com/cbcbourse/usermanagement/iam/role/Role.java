package com.cbcbourse.usermanagement.iam.role;

import com.cbcbourse.usermanagement.common.model.BaseEntity;
import com.cbcbourse.usermanagement.iam.permission.Permission;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.BatchSize;

import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "iam_roles")
public class Role extends BaseEntity {

    /** Code technique immuable (ex : ADMIN). Exposé en autorité "ROLE_ADMIN". */
    @Column(nullable = false, unique = true, length = 50)
    private String code;

    @Column(nullable = false, length = 100)
    private String name;

    @Column(length = 255)
    private String description;

    /** Rôle créé par le bootstrap : son code ne peut pas être supprimé. */
    @Column(name = "system_role", nullable = false)
    private boolean system;

    @ManyToMany
    @BatchSize(size = 50)
    @JoinTable(name = "iam_role_permissions",
            joinColumns = @JoinColumn(name = "role_id"),
            inverseJoinColumns = @JoinColumn(name = "permission_id"))
    private Set<Permission> permissions = new HashSet<>();

    public Role(String code, String name, String description, boolean system) {
        this.code = code;
        this.name = name;
        this.description = description;
        this.system = system;
    }
}
