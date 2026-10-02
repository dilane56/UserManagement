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

/**
 * Gestion des rôles et de leurs permissions.
 * Un rôle regroupe des permissions ; un utilisateur obtient l'union des permissions de tous ses rôles.
 * Le rôle super-administrateur (iam.bootstrap.super-admin-role) est géré automatiquement :
 * il reçoit toutes les permissions et ses permissions ne sont pas modifiables via l'API.
 */
@Service
@RequiredArgsConstructor
@Transactional
public class RoleService {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final UserRepository userRepository;
    private final RoleMapper roleMapper;
    private final IamProperties iamProperties;

    /** Liste tous les rôles, triés par code, avec leurs permissions. */
    @Transactional(readOnly = true)
    public List<RoleResponse> findAll() {
        return roleRepository.findAllByOrderByCodeAsc().stream().map(roleMapper::toResponse).toList();
    }

    /**
     * Renvoie un rôle par son identifiant.
     *
     * @throws ResourceNotFoundException si le rôle n'existe pas (404)
     */
    @Transactional(readOnly = true)
    public RoleResponse findById(Long id) {
        return roleMapper.toResponse(getRole(id));
    }

    /**
     * Crée un rôle personnalisé (non système) avec ses permissions initiales.
     * Le code est normalisé en majuscules (ex : "auditeur" devient "AUDITEUR") et ne pourra plus être modifié.
     *
     * @throws ConflictException   si un rôle porte déjà ce code (409)
     * @throws BadRequestException si une permission demandée n'existe pas (400)
     */
    public RoleResponse create(RoleCreateRequest request) {
        String code = normalizeCode(request.code());
        if (roleRepository.existsByCode(code)) {
            throw new ConflictException("Le rôle " + code + " existe déjà");
        }
        Role role = new Role(code, request.name().trim(), request.description(), false);
        role.setPermissions(resolvePermissions(request.permissions()));
        return roleMapper.toResponse(roleRepository.save(role));
    }

    /**
     * Modifie le libellé et la description d'un rôle. Le code, lui, est immuable
     * car il peut être référencé dans le code ({@code hasRole('...')}) ou la configuration.
     */
    public RoleResponse update(Long id, RoleUpdateRequest request) {
        Role role = getRole(id);
        role.setName(request.name().trim());
        role.setDescription(request.description());
        return roleMapper.toResponse(role);
    }

    /**
     * Remplace l'ensemble des permissions d'un rôle (un ensemble vide retire toutes les permissions).
     * Effet immédiat pour tous les utilisateurs qui possèdent ce rôle.
     *
     * @throws BadRequestException si le rôle est le super-administrateur (géré automatiquement)
     *                             ou si une permission est inconnue (400)
     */
    public RoleResponse replacePermissions(Long id, RolePermissionsRequest request) {
        Role role = getRole(id);
        if (isSuperAdminRole(role)) {
            throw new BadRequestException("Les permissions du rôle " + role.getCode() + " sont gérées automatiquement");
        }
        role.setPermissions(resolvePermissions(request.permissions()));
        return roleMapper.toResponse(role);
    }

    /**
     * Supprime un rôle.
     *
     * @throws BadRequestException si c'est un rôle système créé par le bootstrap (400)
     * @throws ConflictException   si le rôle est encore attribué à au moins un utilisateur (409) :
     *                             il faut d'abord le retirer aux utilisateurs concernés
     */
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

    /**
     * Résout des codes de permission en entités ; échoue si un code est inconnu.
     * Une collection nulle ou vide donne un ensemble vide. Utilisée aussi par le bootstrap.
     *
     * @throws BadRequestException en listant les codes inconnus (400)
     */
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

    /**
     * Résout des codes de rôle en entités ; échoue si un code est inconnu.
     * Utilisée lors de la création d'un compte et du remplacement des rôles d'un utilisateur.
     *
     * @throws BadRequestException en listant les codes inconnus (400)
     */
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

    /** Indique si le rôle est le super-administrateur configuré (iam.bootstrap.super-admin-role). */
    public boolean isSuperAdminRole(Role role) {
        return role.getCode().equals(normalizeCode(iamProperties.getBootstrap().getSuperAdminRole()));
    }

    /**
     * Normalise un code de rôle ou de permission (espaces retirés, majuscules) afin que
     * "admin", " Admin " et "ADMIN" désignent le même rôle.
     *
     * @throws BadRequestException si le code est vide (400)
     */
    public static String normalizeCode(String code) {
        if (code == null || code.isBlank()) {
            throw new BadRequestException("Code vide");
        }
        return code.trim().toUpperCase(Locale.ROOT);
    }

    /** Charge l'entité ou lève une 404. */
    private Role getRole(Long id) {
        return roleRepository.findById(id).orElseThrow(() -> ResourceNotFoundException.of("Rôle", id));
    }
}
