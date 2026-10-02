package com.cbcbourse.usermanagement.iam.user;

import com.cbcbourse.usermanagement.iam.role.Role;
import com.cbcbourse.usermanagement.iam.user.dto.CurrentUserResponse;
import com.cbcbourse.usermanagement.iam.user.dto.UserResponse;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Named;

import java.util.Set;
import java.util.TreeSet;

/** Conversion entité {@link User} → DTO. L'implémentation est générée par MapStruct à la compilation. */
@Mapper
public interface UserMapper {

    /** Représentation publique d'un utilisateur (jamais le mot de passe), rôles sous forme de codes. */
    UserResponse toResponse(User user);

    /** Utilisateur connecté, avec en plus ses permissions effectives (union des permissions de ses rôles). */
    @Mapping(target = "permissions", source = "roles", qualifiedByName = "permissionCodes")
    CurrentUserResponse toCurrentUser(User user);

    /** Codes des rôles, triés par ordre alphabétique. */
    default Set<String> toRoleCodes(Set<Role> roles) {
        Set<String> codes = new TreeSet<>();
        roles.forEach(r -> codes.add(r.getCode()));
        return codes;
    }

    /**
     * Codes des permissions de tous les rôles, sans doublons et triés.
     * Annotée {@code @Named} pour que MapStruct ne l'utilise que là où elle est demandée explicitement.
     */
    @Named("permissionCodes")
    default Set<String> toPermissionCodes(Set<Role> roles) {
        Set<String> codes = new TreeSet<>();
        roles.forEach(r -> r.getPermissions().forEach(p -> codes.add(p.getCode())));
        return codes;
    }
}
