package com.cbcbourse.usermanagement.iam.user;

import com.cbcbourse.usermanagement.iam.role.Role;
import com.cbcbourse.usermanagement.iam.user.dto.CurrentUserResponse;
import com.cbcbourse.usermanagement.iam.user.dto.UserResponse;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Named;

import java.util.Set;
import java.util.TreeSet;

@Mapper
public interface UserMapper {

    UserResponse toResponse(User user);

    @Mapping(target = "permissions", source = "roles", qualifiedByName = "permissionCodes")
    CurrentUserResponse toCurrentUser(User user);

    default Set<String> toRoleCodes(Set<Role> roles) {
        Set<String> codes = new TreeSet<>();
        roles.forEach(r -> codes.add(r.getCode()));
        return codes;
    }

    @Named("permissionCodes")
    default Set<String> toPermissionCodes(Set<Role> roles) {
        Set<String> codes = new TreeSet<>();
        roles.forEach(r -> r.getPermissions().forEach(p -> codes.add(p.getCode())));
        return codes;
    }
}
