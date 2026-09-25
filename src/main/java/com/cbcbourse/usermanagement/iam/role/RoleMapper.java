package com.cbcbourse.usermanagement.iam.role;

import com.cbcbourse.usermanagement.iam.permission.Permission;
import com.cbcbourse.usermanagement.iam.role.dto.RoleResponse;
import org.mapstruct.Mapper;

import java.util.Set;
import java.util.TreeSet;

@Mapper
public interface RoleMapper {

    RoleResponse toResponse(Role role);

    default Set<String> toPermissionCodes(Set<Permission> permissions) {
        Set<String> codes = new TreeSet<>();
        permissions.forEach(p -> codes.add(p.getCode()));
        return codes;
    }
}
