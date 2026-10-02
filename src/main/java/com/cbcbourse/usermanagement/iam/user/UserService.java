package com.cbcbourse.usermanagement.iam.user;

import com.cbcbourse.usermanagement.common.dto.PageResponse;
import com.cbcbourse.usermanagement.common.exception.BadRequestException;
import com.cbcbourse.usermanagement.common.exception.ConflictException;
import com.cbcbourse.usermanagement.common.exception.ResourceNotFoundException;
import com.cbcbourse.usermanagement.iam.role.Role;
import com.cbcbourse.usermanagement.iam.role.RoleService;
import com.cbcbourse.usermanagement.iam.token.RefreshTokenService;
import com.cbcbourse.usermanagement.iam.user.dto.UserCreateRequest;
import com.cbcbourse.usermanagement.iam.user.dto.UserResponse;
import com.cbcbourse.usermanagement.iam.user.dto.UserUpdateRequest;
import com.cbcbourse.usermanagement.security.IamProperties;
import com.cbcbourse.usermanagement.security.SecurityUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Gestion des comptes utilisateurs : recherche, création, modification, rôles, statut et suppression.
 * Les contrôles d'autorisation (permissions USER_*) sont faits dans le contrôleur ; ce service applique
 * les règles métier (unicité de l'email, protection du dernier administrateur, etc.).
 */
@Service
@RequiredArgsConstructor
@Transactional
public class UserService {

    private final UserRepository userRepository;
    private final RoleService roleService;
    private final RefreshTokenService refreshTokenService;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;
    private final IamProperties iamProperties;

    /**
     * Recherche paginée des utilisateurs.
     * Si {@code search} est renseigné, filtre (sans tenir compte de la casse) sur l'email, le nom ou le prénom ;
     * sinon renvoie tous les utilisateurs. Le tri et la taille de page viennent de {@code pageable}.
     */
    @Transactional(readOnly = true)
    public PageResponse<UserResponse> search(String search, Pageable pageable) {
        Page<User> page = (search == null || search.isBlank())
                ? userRepository.findAll(pageable)
                : userRepository.search("%" + search.trim().toLowerCase(Locale.ROOT) + "%", pageable);
        return PageResponse.from(page.map(userMapper::toResponse));
    }

    /**
     * Renvoie un utilisateur par son identifiant.
     *
     * @throws ResourceNotFoundException si aucun utilisateur ne porte cet identifiant (404)
     */
    @Transactional(readOnly = true)
    public UserResponse findById(Long id) {
        return userMapper.toResponse(getUser(id));
    }

    /**
     * Renvoie un utilisateur par son email (comparaison insensible à la casse et aux espaces).
     *
     * @throws ResourceNotFoundException si aucun compte n'utilise cet email (404)
     */
    @Transactional(readOnly = true)
    public UserResponse findByEmail(String email) {
        String normalized = normalizeEmail(email);
        return userRepository.findByEmail(normalized)
                .map(userMapper::toResponse)
                .orElseThrow(() -> ResourceNotFoundException.of("Utilisateur", normalized));
    }

    /**
     * Création d'un compte par un administrateur (POST /api/users).
     * Délègue à {@link #createAccount} et renvoie la représentation publique (sans mot de passe).
     */
    public UserResponse create(UserCreateRequest request) {
        User user = createAccount(request.nom(), request.prenom(), request.email(), request.password(), request.roles());
        return userMapper.toResponse(user);
    }

    /**
     * Crée un compte. Sans rôle explicite, le rôle par défaut (iam.registration.default-role) est attribué.
     * Méthode réutilisable par l'inscription libre et par les futurs modules.
     */
    public User createAccount(String nom, String prenom, String email, String rawPassword, Collection<String> roleCodes) {
        String normalizedEmail = normalizeEmail(email);
        if (userRepository.existsByEmail(normalizedEmail)) {
            throw new ConflictException("Email déjà utilisé");
        }
        Collection<String> codes = (roleCodes == null || roleCodes.isEmpty())
                ? List.of(iamProperties.getRegistration().getDefaultRole())
                : roleCodes;

        User user = new User();
        user.setNom(nom.trim());
        user.setPrenom(prenom == null ? null : prenom.trim());
        user.setEmail(normalizedEmail);
        user.setPassword(passwordEncoder.encode(rawPassword));
        user.setEnabled(true);
        user.setRoles(roleService.resolveRoles(codes));
        return userRepository.save(user);
    }

    /**
     * Met à jour le nom, le prénom et l'email d'un utilisateur.
     * Les rôles, le statut et le mot de passe ont leurs propres méthodes dédiées.
     *
     * @throws ConflictException si le nouvel email est déjà utilisé par un autre compte (409)
     */
    public UserResponse update(Long id, UserUpdateRequest request) {
        User user = getUser(id);
        String email = normalizeEmail(request.email());
        if (!user.getEmail().equals(email) && userRepository.existsByEmail(email)) {
            throw new ConflictException("Email déjà utilisé");
        }
        user.setNom(request.nom().trim());
        user.setPrenom(request.prenom().trim());
        user.setEmail(email);
        return userMapper.toResponse(user);
    }

    /**
     * Active ou désactive un compte.
     * Un compte désactivé ne peut plus se connecter, ses refresh tokens sont révoqués et ses access tokens
     * en cours sont refusés dès la requête suivante (les droits sont relus en base à chaque appel).
     *
     * @throws BadRequestException si l'utilisateur tente de se désactiver lui-même
     *                             ou s'il s'agit du dernier administrateur actif (400)
     */
    public UserResponse updateStatus(Long id, boolean enabled) {
        User user = getUser(id);
        if (!enabled) {
            ensureNotCurrentUser(user, "désactiver votre propre compte");
            ensureNotLastSuperAdmin(user);
            refreshTokenService.revokeAll(user);
        }
        user.setEnabled(enabled);
        return userMapper.toResponse(user);
    }

    /**
     * Remplace l'ensemble des rôles d'un utilisateur par ceux fournis (les rôles absents sont retirés).
     * Le changement de droits prend effet immédiatement, sans attendre un nouveau token.
     *
     * @throws BadRequestException si un code de rôle est inconnu, ou si l'opération retirerait le rôle
     *                             super-administrateur au dernier administrateur actif (400)
     */
    public UserResponse replaceRoles(Long id, Set<String> roleCodes) {
        User user = getUser(id);
        Set<Role> roles = roleService.resolveRoles(roleCodes);
        boolean keepsSuperAdmin = roles.stream().anyMatch(roleService::isSuperAdminRole);
        if (!keepsSuperAdmin) {
            ensureNotLastSuperAdmin(user);
        }
        user.setRoles(roles);
        return userMapper.toResponse(user);
    }

    /**
     * Réinitialisation du mot de passe par un administrateur (sans connaître l'ancien).
     * Toutes les sessions de l'utilisateur (refresh tokens) sont révoquées par sécurité.
     */
    public void resetPassword(Long id, String newPassword) {
        User user = getUser(id);
        user.setPassword(passwordEncoder.encode(newPassword));
        refreshTokenService.revokeAll(user);
    }

    /**
     * Supprime définitivement un utilisateur et ses refresh tokens.
     *
     * @throws BadRequestException si l'utilisateur tente de se supprimer lui-même
     *                             ou s'il s'agit du dernier administrateur actif (400)
     */
    public void delete(Long id) {
        User user = getUser(id);
        ensureNotCurrentUser(user, "supprimer votre propre compte");
        ensureNotLastSuperAdmin(user);
        refreshTokenService.deleteAll(user);
        userRepository.delete(user);
    }

    /**
     * Normalise un email (espaces retirés, minuscules) pour garantir l'unicité quelle que soit la saisie :
     * "Jean@Mail.com " et "jean@mail.com" désignent le même compte.
     *
     * @throws BadRequestException si l'email est vide (400)
     */
    public static String normalizeEmail(String email) {
        if (email == null || email.isBlank()) {
            throw new BadRequestException("Email obligatoire");
        }
        return email.trim().toLowerCase(Locale.ROOT);
    }

    /** Charge l'entité ou lève une 404. */
    private User getUser(Long id) {
        return userRepository.findById(id).orElseThrow(() -> ResourceNotFoundException.of("Utilisateur", id));
    }

    /** Interdit à l'utilisateur connecté d'effectuer l'action décrite par {@code action} sur son propre compte. */
    private void ensureNotCurrentUser(User user, String action) {
        SecurityUtils.currentUser()
                .filter(current -> current.getId().equals(user.getId()))
                .ifPresent(current -> {
                    throw new BadRequestException("Vous ne pouvez pas " + action);
                });
    }

    /** Empêche de perdre le dernier compte actif disposant du rôle super-administrateur. */
    private void ensureNotLastSuperAdmin(User user) {
        String superAdmin = RoleService.normalizeCode(iamProperties.getBootstrap().getSuperAdminRole());
        if (user.isEnabled() && user.hasRole(superAdmin)
                && userRepository.countByRolesCodeAndEnabledTrue(superAdmin) <= 1) {
            throw new BadRequestException("Opération impossible : c'est le dernier administrateur actif");
        }
    }
}
