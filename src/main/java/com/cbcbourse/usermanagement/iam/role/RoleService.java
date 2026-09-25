package com.cbcbourse.usermanagement.iam.role;

import com.cbcbourse.usermanagement.common.exception.BadRequestException;
import com.cbcbourse.usermanagement.common.exception.ConflictException;
import com.cbcbourse.usermanagement.common.exception.ResourceNotFoundException;
import com.cbcbourse.usermanagement.iam.permission.Permission;
import com.cbcbourse.usermanagement.iam.permission.PermissionRepository;
import com.cbcbourse.usermanagement.iam.role.dto.RoleCreateRequest;
import com.cbcbourse.usermanagement.iam.role.dto.RolePermissionsRequest;
import com.cbcbourse.usermanagement.iam.role.dto.RoleResponse;
import com.cbcbourse.usermanagement.iam.role.dto.RoleUpdateRequest;
import com.cbcbourse.usermanagement.iam.user.UserRepository;
import com.cbcbourse.usermanagement.security.IamProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional
public class RoleService {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final UserRepository userRepository;
    private final RoleMapper roleMapper;
    private final IamProperties iamProperties;

    @Transactional(readOnly = true)
    public List<RoleResponse> findAll() {
        return roleRepository.findAllByOrderByCodeAsc().stream().map(roleMapper::toResponse).toList();
    }

    @Transactional(readOnly = true)
    public RoleResponse findById(Long id) {
        return roleMapper.toResponse(getRole(id));
    }

    public RoleResponse create(RoleCreateRequest request) {
        String code = normalizeCode(request.code());
        if (roleRepository.existsByCode(code)) {
            throw new ConflictException("Le rôle " + code + " existe déjà");
        }
        Role role = new Role(code, request.name().trim(), request.description(), false);
        role.setPermissions(resolvePermissions(request.permissions()));
        return roleMapper.toResponse(roleRepository.save(role));
    }

    public RoleResponse update(Long id, RoleUpdateRequest request) {
        Role role = getRole(id);
        role.setName(request.name().trim());
        role.setDescription(request.description());
        return roleMapper.toResponse(role);
    }

    public RoleResponse replacePermissions(Long id, RolePermissionsRequest request) {
        Role role = getRole(id);
        if (isSuperAdminRole(role)) {
            throw new BadRequestException("Les permissions du rôle " + role.getCode() + " sont gérées automatiquement");
        }
        role.setPermissions(resolvePermissions(request.permissions()));
        return roleMapper.toResponse(role);
    }

    public void delete(Long id) {
        Role role = getRole(id);
        if (role.isSystem()) {
            throw new BadRequestException("Le rôle système " + role.getCode() + " ne peut pas être supprimé");
        }
        if (userRepository.existsByRolesId(id)) {
            throw new ConflictException("Le rôle " + role.getCode() + " est encore attribué à des utilisateurs");
        }
        roleRepository.delete(role);
    }

    /** Résout des codes de permission en entités ; échoue si un code est inconnu. */
    @Transactional(readOnly = true)
    public Set<Permission> resolvePermissions(Collection<String> codes) {
        if (codes == null || codes.isEmpty()) {
            return new HashSet<>();
        }
        Set<String> normalized = codes.stream().map(RoleService::normalizeCode).collect(Collectors.toSet());
        List<Permission> found = permissionRepository.findByCodeIn(normalized);
        if (found.size() != normalized.size()) {
            Set<String> unknown = new TreeSet<>(normalized);
            found.forEach(p -> unknown.remove(p.getCode()));
            throw new BadRequestException("Permissions inconnues : " + unknown);
        }
        return new HashSet<>(found);
    }

    /** Résout des codes de rôle en entités ; échoue si un code est inconnu. */
    @Transactional(readOnly = true)
    public Set<Role> resolveRoles(Collection<String> codes) {
        Set<String> normalized = codes.stream().map(RoleService::normalizeCode).collect(Collectors.toSet());
        List<Role> found = roleRepository.findByCodeIn(normalized);
        if (found.size() != normalized.size()) {
            Set<String> unknown = new TreeSet<>(normalized);
            found.forEach(r -> unknown.remove(r.getCode()));
            throw new BadRequestException("Rôles inconnus : " + unknown);
        }
        return new HashSet<>(found);
    }

    public boolean isSuperAdminRole(Role role) {
        return role.getCode().equals(normalizeCode(iamProperties.getBootstrap().getSuperAdminRole()));
    }

    public static String normalizeCode(String code) {
        if (code == null || code.isBlank()) {
            throw new BadRequestException("Code vide");
        }
        return code.trim().toUpperCase(Locale.ROOT);
    }

    private Role getRole(Long id) {
        return roleRepository.findById(id).orElseThrow(() -> ResourceNotFoundException.of("Rôle", id));
    }
}
