package com.cbcbourse.usermanagement.iam.role;

import com.cbcbourse.usermanagement.iam.permission.IamPermissions;
import com.cbcbourse.usermanagement.iam.role.dto.RoleCreateRequest;
import com.cbcbourse.usermanagement.iam.role.dto.RolePermissionsRequest;
import com.cbcbourse.usermanagement.iam.role.dto.RoleResponse;
import com.cbcbourse.usermanagement.iam.role.dto.RoleUpdateRequest;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Administration des rôles et de leurs permissions. Chaque endpoint exige une permission ROLE_*
 * vérifiée par {@code @PreAuthorize} (403 sinon) ; les règles métier sont appliquées par {@link RoleService}.
 * Chaque méthode est décrite par son {@code @Operation} (Swagger).
 */
@Tag(name = "Rôles")
@RestController
@RequestMapping("/api/roles")
@RequiredArgsConstructor
public class RoleController {

    private final RoleService roleService;

    @Operation(summary = "Lister les rôles")
    @GetMapping
    @PreAuthorize("hasAuthority('" + IamPermissions.ROLE_READ + "')")
    public List<RoleResponse> findAll() {
        return roleService.findAll();
    }

    @Operation(summary = "Détail d'un rôle")
    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('" + IamPermissions.ROLE_READ + "')")
    public RoleResponse findById(@PathVariable Long id) {
        return roleService.findById(id);
    }

    @Operation(summary = "Créer un rôle")
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('" + IamPermissions.ROLE_CREATE + "')")
    public RoleResponse create(@Valid @RequestBody RoleCreateRequest request) {
        return roleService.create(request);
    }

    @Operation(summary = "Modifier le nom et la description d'un rôle")
    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('" + IamPermissions.ROLE_UPDATE + "')")
    public RoleResponse update(@PathVariable Long id, @Valid @RequestBody RoleUpdateRequest request) {
        return roleService.update(id, request);
    }

    @Operation(summary = "Remplacer les permissions d'un rôle")
    @PutMapping("/{id}/permissions")
    @PreAuthorize("hasAuthority('" + IamPermissions.ROLE_UPDATE + "')")
    public RoleResponse replacePermissions(@PathVariable Long id, @Valid @RequestBody RolePermissionsRequest request) {
        return roleService.replacePermissions(id, request);
    }

    @Operation(summary = "Supprimer un rôle (non système et non attribué)")
    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PreAuthorize("hasAuthority('" + IamPermissions.ROLE_DELETE + "')")
    public void delete(@PathVariable Long id) {
        roleService.delete(id);
    }
}
