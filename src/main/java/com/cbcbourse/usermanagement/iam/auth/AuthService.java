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

    /** Rotation : l'ancien refresh token est révoqué et un nouveau couple de tokens est émis. */
    @Transactional(noRollbackFor = ApiException.class)
    public AuthResponse refresh(RefreshTokenRequest request) {
        User user = refreshTokenService.consume(request.refreshToken());
        if (!user.isEnabled()) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Compte désactivé");
        }
        return issueTokens(user);
    }

    public void logout(RefreshTokenRequest request) {
        refreshTokenService.revoke(request.refreshToken());
    }

    public UserResponse register(RegisterRequest request) {
        if (!iamProperties.getRegistration().isEnabled()) {
            throw new ApiException(HttpStatus.FORBIDDEN, "L'inscription libre est désactivée");
        }
        User user = userService.createAccount(request.nom(), request.prenom(), request.email(), request.password(), null);
        return userMapper.toResponse(user);
    }

    @Transactional(readOnly = true)
    public CurrentUserResponse me() {
        return userMapper.toCurrentUser(currentUser());
    }

    public CurrentUserResponse updateProfile(UpdateProfileRequest request) {
        User user = currentUser();
        user.setNom(request.nom().trim());
        user.setPrenom(request.prenom().trim());
        return userMapper.toCurrentUser(user);
    }

    /** Change le mot de passe et révoque toutes les sessions (refresh tokens) de l'utilisateur. */
    public void changePassword(ChangePasswordRequest request) {
        User user = currentUser();
        if (!passwordEncoder.matches(request.currentPassword(), user.getPassword())) {
            throw new BadRequestException("Mot de passe actuel incorrect");
        }
        user.setPassword(passwordEncoder.encode(request.newPassword()));
        refreshTokenService.revokeAll(user);
    }

    private AuthResponse issueTokens(User user) {
        UserPrincipal principal = UserPrincipal.from(user);
        String accessToken = jwtService.generateAccessToken(principal);
        String refreshToken = refreshTokenService.issue(user);
        return AuthResponse.bearer(accessToken, refreshToken, jwtService.getAccessTokenTtlSeconds(),
                userMapper.toCurrentUser(user));
    }

    private User currentUser() {
        Long id = SecurityUtils.requireCurrentUserId();
        return userRepository.findById(id).orElseThrow(() -> ResourceNotFoundException.of("Utilisateur", id));
    }
}
