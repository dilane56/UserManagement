package com.cbcbourse.usermanagement.security;

import com.cbcbourse.usermanagement.iam.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * Charge un utilisateur par son email avec ses rôles et permissions en une seule requête.
     * Appelée au login (via Spring Security) et à chaque requête authentifiée (via le filtre JWT).
     *
     * @throws UsernameNotFoundException si aucun compte ne correspond (traduit en 401, sans préciser la cause)
     */
    @Override
    @Transactional(readOnly = true)
    public UserPrincipal loadUserByUsername(String username) throws UsernameNotFoundException {
        String email = username == null ? "" : username.trim().toLowerCase(Locale.ROOT);
        return userRepository.findWithAuthoritiesByEmail(email)
                .map(UserPrincipal::from)
                .orElseThrow(() -> new UsernameNotFoundException("Utilisateur introuvable"));
    }
}
