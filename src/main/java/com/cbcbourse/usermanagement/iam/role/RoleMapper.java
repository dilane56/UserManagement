package com.cbcbourse.usermanagement.iam.role;

import com.cbcbourse.usermanagement.iam.permission.Permission;
import com.cbcbourse.usermanagement.iam.role.dto.RoleResponse;
import org.mapstruct.Mapper;

import java.util.Set;
import java.util.TreeSet;

/** Conversion entité {@link Role} → DTO. L'implémentation est générée par MapStruct à la compilation. */
@Mapper
public interface RoleMapper {

    /** Représentation d'un rôle avec les codes de ses permissions. */
    RoleResponse toResponse(Role role);

    /** Codes des permissions, triés par ordre alphabétique. */
    default Set<String> toPermissionCodes(Set<Permission> permissions) {
        Set<String> codes = new TreeSet<>();
        permissions.forEach(p -> codes.add(p.getCode()));
        return codes;
    }
}
