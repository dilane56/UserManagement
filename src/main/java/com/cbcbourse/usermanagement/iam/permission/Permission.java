package com.cbcbourse.usermanagement.iam.permission;

import com.cbcbourse.usermanagement.common.model.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Permission atomique (ex : USER_READ). Elle devient une autorité Spring Security
 * et se vérifie avec {@code @PreAuthorize("hasAuthority('USER_READ')")}.
 */
@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "iam_permissions")
public class Permission extends BaseEntity {

    @Column(nullable = false, unique = true, length = 100)
    private String code;

    @Column(length = 255)
    private String description;

    /** Module fonctionnel propriétaire de la permission (IAM, PORTFOLIO...). */
    @Column(name = "module_name", length = 50)
    private String module;

    public Permission(String code, String description, String module) {
        this.code = code;
        this.description = description;
        this.module = module;
    }
}
