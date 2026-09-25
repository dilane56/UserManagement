package com.cbcbourse.usermanagement.iam.auth;

import com.cbcbourse.usermanagement.iam.auth.dto.*;
import com.cbcbourse.usermanagement.iam.user.dto.CurrentUserResponse;
import com.cbcbourse.usermanagement.iam.user.dto.UserResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@Tag(name = "Authentification")
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @Operation(summary = "Se connecter (renvoie access token + refresh token)")
    @PostMapping("/login")
    public AuthResponse login(@Valid @RequestBody LoginRequest request) {
        return authService.login(request);
    }

    @Operation(summary = "Renouveler les tokens à partir d'un refresh token")
    @PostMapping("/refresh")
    public AuthResponse refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return authService.refresh(request);
    }

    @Operation(summary = "Se déconnecter (révoque le refresh token)")
    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@Valid @RequestBody RefreshTokenRequest request) {
        authService.logout(request);
    }

    @Operation(summary = "Inscription libre (si iam.registration.enabled=true)")
    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public UserResponse register(@Valid @RequestBody RegisterRequest request) {
        return authService.register(request);
    }

    @Operation(summary = "Utilisateur connecté, avec ses rôles et permissions")
    @GetMapping("/me")
    public CurrentUserResponse me() {
        return authService.me();
    }

    @Operation(summary = "Modifier son profil")
    @PutMapping("/me")
    public CurrentUserResponse updateProfile(@Valid @RequestBody UpdateProfileRequest request) {
        return authService.updateProfile(request);
    }

    @Operation(summary = "Changer son mot de passe (révoque toutes ses sessions)")
    @PutMapping("/me/password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void changePassword(@Valid @RequestBody ChangePasswordRequest request) {
        authService.changePassword(request);
    }
}
