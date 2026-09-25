package com.cbcbourse.usermanagement.security;

import com.cbcbourse.usermanagement.iam.role.Role;
import com.cbcbourse.usermanagement.iam.user.User;
import lombok.Getter;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.*;

/**
 * Utilisateur authentifié. Ses autorités contiennent :
 * <ul>
 *     <li>ses rôles préfixés "ROLE_" → {@code hasRole('ADMIN')}</li>
 *     <li>ses permissions → {@code hasAuthority('USER_READ')}</li>
 * </ul>
 */
@Getter
public class UserPrincipal implements UserDetails, CredentialsContainer {

    public static final String ROLE_PREFIX = "ROLE_";

    private final Long id;
    private final String email;
    private String password;
    private final boolean enabled;
    private final Set<String> roles;
    private final Set<String> permissions;
    private final Collection<? extends GrantedAuthority> authorities;

    private UserPrincipal(Long id, String email, String password, boolean enabled,
                          Set<String> roles, Set<String> permissions) {
        this.id = id;
        this.email = email;
        this.password = password;
        this.enabled = enabled;
        this.roles = Collections.unmodifiableSet(roles);
        this.permissions = Collections.unmodifiableSet(permissions);

        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        roles.forEach(r -> grantedAuthorities.add(new SimpleGrantedAuthority(ROLE_PREFIX + r)));
        permissions.forEach(p -> grantedAuthorities.add(new SimpleGrantedAuthority(p)));
        this.authorities = Collections.unmodifiableList(grantedAuthorities);
    }

    public static UserPrincipal from(User user) {
        Set<String> roles = new TreeSet<>();
        Set<String> permissions = new TreeSet<>();
        for (Role role : user.getRoles()) {
            roles.add(role.getCode());
            role.getPermissions().forEach(p -> permissions.add(p.getCode()));
        }
        return new UserPrincipal(user.getId(), user.getEmail(), user.getPassword(), user.isEnabled(), roles, permissions);
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public void eraseCredentials() {
        this.password = null;
    }
}
