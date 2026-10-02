package com.cbcbourse.usermanagement.iam.auth;

import com.cbcbourse.usermanagement.common.exception.ApiException;
import com.cbcbourse.usermanagement.common.exception.BadRequestException;
import com.cbcbourse.usermanagement.common.exception.ResourceNotFoundException;
import com.cbcbourse.usermanagement.iam.auth.dto.*;
import com.cbcbourse.usermanagement.iam.token.RefreshTokenService;
import com.cbcbourse.usermanagement.iam.user.User;
import com.cbcbourse.usermanagement.iam.user.UserMapper;
import com.cbcbourse.usermanagement.iam.user.UserRepository;
import com.cbcbourse.usermanagement.iam.user.UserService;
import com.cbcbourse.usermanagement.iam.user.dto.CurrentUserResponse;
import com.cbcbourse.usermanagement.iam.user.dto.UserResponse;
import com.cbcbourse.usermanagement.security.IamProperties;
import com.cbcbourse.usermanagement.security.JwtService;
import com.cbcbourse.usermanagement.security.SecurityUtils;
import com.cbcbourse.usermanagement.security.UserPrincipal;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/**
 * Authentification et opérations de l'utilisateur sur son propre compte :
 * connexion, renouvellement des tokens, déconnexion, inscription, profil et mot de passe.
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final UserRepository userRepository;
    private final UserService userService;
    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;
    private final IamProperties iamProperties;

    /**
     * Connecte un utilisateur à partir de son email et de son mot de passe.
     * La vérification est déléguée à Spring Security (mot de passe, compte actif), puis la date de
     * dernière connexion est enregistrée et un couple access token + refresh token est émis.
     *
     * @throws org.springframework.security.authentication.BadCredentialsException identifiants invalides (401)
     * @throws org.springframework.security.authentication.DisabledException       compte désactivé (401)
     */
    public AuthResponse login(LoginRequest request) {
        // Ne jamais journaliser l'email ou le mot de passe (données sensibles).
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                UserService.normalizeEmail(request.email()), request.password()));

        User user = userRepository.findByEmail(UserService.normalizeEmail(request.email()))
                .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "Identifiants invalides"));
        user.setLastLoginAt(Instant.now());
        log.info("Connexion réussie (utilisateur id={})", user.getId());
        return issueTokens(user);
    }

    /**
     * Rotation : l'ancien refresh token est révoqué et un nouveau couple de tokens est émis.
     * À appeler par le front quand l'access token expire. {@code noRollbackFor} garantit que la révocation
     * de toutes les sessions, en cas de réutilisation d'un token volé, est bien enregistrée malgré l'erreur 401.
     *
     * @throws ApiException 401 si le refresh token est inconnu, expiré, révoqué, ou si le compte est désactivé
     */
    @Transactional(noRollbackFor = ApiException.class)
    public AuthResponse refresh(RefreshTokenRequest request) {
        User user = refreshTokenService.consume(request.refreshToken());
        if (!user.isEnabled()) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Compte désactivé");
        }
        return issueTokens(user);
    }

    /**
     * Déconnexion : révoque le refresh token fourni pour qu'il ne puisse plus être renouvelé.
     * L'access token reste valide jusqu'à son expiration (courte) : le front doit simplement l'oublier.
     * Ne lève pas d'erreur si le token est déjà révoqué ou inconnu.
     */
    public void logout(RefreshTokenRequest request) {
        refreshTokenService.revoke(request.refreshToken());
    }

    /**
     * Inscription libre : crée un compte avec le rôle par défaut.
     * Disponible seulement si iam.registration.enabled=true.
     *
     * @throws ApiException      403 si l'inscription libre est désactivée
     * @throws com.cbcbourse.usermanagement.common.exception.ConflictException 409 si l'email est déjà utilisé
     */
    public UserResponse register(RegisterRequest request) {
        if (!iamProperties.getRegistration().isEnabled()) {
            throw new ApiException(HttpStatus.FORBIDDEN, "L'inscription libre est désactivée");
        }
        User user = userService.createAccount(request.nom(), request.prenom(), request.email(), request.password(), null);
        return userMapper.toResponse(user);
    }

    /** Renvoie l'utilisateur connecté avec ses rôles et ses permissions effectives (utile au front pour adapter l'affichage). */
    @Transactional(readOnly = true)
    public CurrentUserResponse me() {
        return userMapper.toCurrentUser(currentUser());
    }

    /** Permet à l'utilisateur connecté de modifier son nom et son prénom (pas son email ni ses rôles). */
    public CurrentUserResponse updateProfile(UpdateProfileRequest request) {
        User user = currentUser();
        user.setNom(request.nom().trim());
        user.setPrenom(request.prenom().trim());
        return userMapper.toCurrentUser(user);
    }

    /**
     * Change le mot de passe et révoque toutes les sessions (refresh tokens) de l'utilisateur.
     * L'ancien mot de passe est exigé pour éviter qu'une session laissée ouverte suffise à prendre le compte.
     *
     * @throws BadRequestException si le mot de passe actuel est incorrect (400)
     */
    public void changePassword(ChangePasswordRequest request) {
        User user = currentUser();
        if (!passwordEncoder.matches(request.currentPassword(), user.getPassword())) {
            throw new BadRequestException("Mot de passe actuel incorrect");
        }
        user.setPassword(passwordEncoder.encode(request.newPassword()));
        refreshTokenService.revokeAll(user);
    }

    /** Génère l'access token JWT (rôles et permissions inclus) et un nouveau refresh token pour l'utilisateur. */
    private AuthResponse issueTokens(User user) {
        UserPrincipal principal = UserPrincipal.from(user);
        String accessToken = jwtService.generateAccessToken(principal);
        String refreshToken = refreshTokenService.issue(user);
        return AuthResponse.bearer(accessToken, refreshToken, jwtService.getAccessTokenTtlSeconds(),
                userMapper.toCurrentUser(user));
    }

    /** Recharge depuis la base l'entité de l'utilisateur authentifié sur la requête en cours. */
    private User currentUser() {
        Long id = SecurityUtils.requireCurrentUserId();
        return userRepository.findById(id).orElseThrow(() -> ResourceNotFoundException.of("Utilisateur", id));
    }
}
