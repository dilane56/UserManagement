package com.cbcbourse.usermanagement.iam.permission;

import com.cbcbourse.usermanagement.iam.permission.dto.PermissionResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Les permissions sont déclarées dans le code ({@link PermissionProvider}) : l'API est en lecture seule,
 * car une permission n'a de sens que si le code la vérifie.
 */
@Tag(name = "Permissions")
@RestController
@RequestMapping("/api/permissions")
@RequiredArgsConstructor
public class PermissionController {

    private final PermissionRepository permissionRepository;

    @Operation(summary = "Lister toutes les permissions disponibles")
    @GetMapping
    @Transactional(readOnly = true)
    @PreAuthorize("hasAuthority('" + IamPermissions.PERMISSION_READ + "')")
    public List<PermissionResponse> findAll() {
        return permissionRepository.findAllByOrderByModuleAscCodeAsc().stream()
                .map(p -> new PermissionResponse(p.getId(), p.getCode(), p.getDescription(), p.getModule()))
                .toList();
    }
}
