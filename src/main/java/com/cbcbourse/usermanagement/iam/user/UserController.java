package com.cbcbourse.usermanagement.iam.user;

import com.cbcbourse.usermanagement.common.dto.PageResponse;
import com.cbcbourse.usermanagement.iam.permission.IamPermissions;
import com.cbcbourse.usermanagement.iam.user.dto.*;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

/**
 * Administration des utilisateurs. Chaque endpoint exige une permission USER_* vérifiée par {@code @PreAuthorize}
 * (403 sinon) ; les règles métier sont appliquées par {@link UserService}.
 * Chaque méthode est décrite par son {@code @Operation} (Swagger).
 */
@Tag(name = "Utilisateurs")
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @Operation(summary = "Rechercher les utilisateurs (paginé)",
            description = "Paramètres : search (email, nom, prénom), page, size, sort (ex : sort=nom,asc)")
    @GetMapping
    @PreAuthorize("hasAuthority('" + IamPermissions.USER_READ + "')")
    public PageResponse<UserResponse> search(@RequestParam(required = false) String search,
                                             @PageableDefault(size = 20, sort = "id", direction = Sort.Direction.ASC)
                                             Pageable pageable) {
        return userService.search(search, pageable);
    }

    @Operation(summary = "Détail d'un utilisateur")
    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('" + IamPermissions.USER_READ + "')")
    public UserResponse findById(@PathVariable Long id) {
        return userService.findById(id);
    }

    @Operation(summary = "Rechercher un utilisateur par email")
    @GetMapping("/by-email")
    @PreAuthorize("hasAuthority('" + IamPermissions.USER_READ + "')")
    public UserResponse findByEmail(@RequestParam String email) {
        return userService.findByEmail(email);
    }

    @Operation(summary = "Créer un utilisateur")
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('" + IamPermissions.USER_CREATE + "')")
    public UserResponse create(@Valid @RequestBody UserCreateRequest request) {
        return userService.create(request);
    }

    @Operation(summary = "Modifier les informations d'un utilisateur")
    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('" + IamPermissions.USER_UPDATE + "')")
    public UserResponse update(@PathVariable Long id, @Valid @RequestBody UserUpdateRequest request) {
        return userService.update(id, request);
    }

    @Operation(summary = "Activer / désactiver un utilisateur")
    @PatchMapping("/{id}/status")
    @PreAuthorize("hasAuthority('" + IamPermissions.USER_UPDATE + "')")
    public UserResponse updateStatus(@PathVariable Long id, @Valid @RequestBody UserStatusRequest request) {
        return userService.updateStatus(id, request.enabled());
    }

    @Operation(summary = "Remplacer les rôles d'un utilisateur")
    @PutMapping("/{id}/roles")
    @PreAuthorize("hasAuthority('" + IamPermissions.USER_UPDATE + "')")
    public UserResponse replaceRoles(@PathVariable Long id, @Valid @RequestBody UserRolesRequest request) {
        return userService.replaceRoles(id, request.roles());
    }

    @Operation(summary = "Réinitialiser le mot de passe d'un utilisateur (révoque ses sessions)")
    @PutMapping("/{id}/password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PreAuthorize("hasAuthority('" + IamPermissions.USER_UPDATE + "')")
    public void resetPassword(@PathVariable Long id, @Valid @RequestBody PasswordResetRequest request) {
        userService.resetPassword(id, request.newPassword());
    }

    @Operation(summary = "Supprimer un utilisateur")
    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PreAuthorize("hasAuthority('" + IamPermissions.USER_DELETE + "')")
    public void delete(@PathVariable Long id) {
        userService.delete(id);
    }
}
