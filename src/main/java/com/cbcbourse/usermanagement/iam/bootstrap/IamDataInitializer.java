package com.cbcbourse.usermanagement.iam.bootstrap;

import com.cbcbourse.usermanagement.iam.permission.Permission;
import com.cbcbourse.usermanagement.iam.permission.PermissionDefinition;
import com.cbcbourse.usermanagement.iam.permission.PermissionProvider;
import com.cbcbourse.usermanagement.iam.permission.PermissionRepository;
import com.cbcbourse.usermanagement.iam.role.Role;
import com.cbcbourse.usermanagement.iam.role.RoleRepository;
import com.cbcbourse.usermanagement.iam.role.RoleService;
import com.cbcbourse.usermanagement.iam.user.User;
import com.cbcbourse.usermanagement.iam.user.UserRepository;
import com.cbcbourse.usermanagement.iam.user.UserService;
import com.cbcbourse.usermanagement.security.IamProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.util.*;

/**
 * Initialise les données IAM au démarrage (idempotent) :
 * <ol>
 *     <li>synchronise les permissions déclarées par tous les {@link PermissionProvider} ;</li>
 *     <li>crée les rôles de iam.bootstrap.roles s'ils n'existent pas ;</li>
 *     <li>donne toutes les permissions au rôle super-admin ;</li>
 *     <li>crée le premier administrateur s'il n'existe aucun compte super-admin.</li>
 * </ol>
 */
@Slf4j
@Component
@Order(0)
@RequiredArgsConstructor
@ConditionalOnProperty(prefix = "iam.bootstrap", name = "enabled", havingValue = "true", matchIfMissing = true)
public class IamDataInitializer implements ApplicationRunner {

    private final List<PermissionProvider> permissionProviders;
    private final PermissionRepository permissionRepository;
    private final RoleRepository roleRepository;
    private final RoleService roleService;
    private final UserRepository userRepository;
    private final UserService userService;
    private final IamProperties iamProperties;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        syncPermissions();
        seedRoles();
        Role superAdmin = syncSuperAdminRole();
        seedAdmin(superAdmin);
    }

    private void syncPermissions() {
        Map<String, PermissionDefinition> declared = new LinkedHashMap<>();
        for (PermissionProvider provider : permissionProviders) {
            for (PermissionDefinition definition : provider.permissions()) {
                String code = RoleService.normalizeCode(definition.code());
                PermissionDefinition previous = declared.putIfAbsent(code, definition);
                if (previous != null) {
                    log.warn("Permission {} déclarée plusieurs fois, seule la première déclaration est retenue", code);
                }
            }
        }

        Map<String, Permission> existing = new HashMap<>();
        permissionRepository.findAll().forEach(p -> existing.put(p.getCode(), p));

        declared.forEach((code, definition) -> {
            Permission permission = existing.get(code);
            if (permission == null) {
                permissionRepository.save(new Permission(code, definition.description(), definition.module()));
                log.info("Permission créée : {}", code);
            } else {
                permission.setDescription(definition.description());
                permission.setModule(definition.module());
            }
        });

        existing.keySet().stream()
                .filter(code -> !declared.containsKey(code))
                .forEach(code -> log.warn("Permission {} présente en base mais plus déclarée dans le code", code));
    }

    private void seedRoles() {
        for (IamProperties.RoleSeed seed : iamProperties.getBootstrap().getRoles()) {
            String code = RoleService.normalizeCode(seed.getCode());
            if (roleRepository.existsByCode(code)) {
                continue;
            }
            Role role = new Role(code, seed.getName() != null ? seed.getName() : code, seed.getDescription(), true);
            role.setPermissions(roleService.resolvePermissions(seed.getPermissions()));
            roleRepository.save(role);
            log.info("Rôle créé : {}", code);
        }
    }

    private Role syncSuperAdminRole() {
        String code = RoleService.normalizeCode(iamProperties.getBootstrap().getSuperAdminRole());
        Role role = roleRepository.findByCode(code).orElseGet(() -> {
            log.info("Rôle super-administrateur créé : {}", code);
            return roleRepository.save(new Role(code, "Administrateur", "Accès complet", true));
        });
        role.setSystem(true);
        role.setPermissions(new HashSet<>(permissionRepository.findAll()));
        return role;
    }

    private void seedAdmin(Role superAdmin) {
        if (userRepository.countByRolesCodeAndEnabledTrue(superAdmin.getCode()) > 0) {
            return;
        }
        IamProperties.AdminSeed admin = iamProperties.getBootstrap().getAdmin();
        if (admin.getEmail() == null || admin.getEmail().isBlank()) {
            log.warn("Aucun administrateur actif et iam.bootstrap.admin.email non défini : aucun compte admin créé");
            return;
        }
        String email = UserService.normalizeEmail(admin.getEmail());
        Optional<User> existing = userRepository.findByEmail(email);
        if (existing.isPresent()) {
            // Le compte existe mais n'a pas (ou plus) le rôle admin actif : on le lui rend.
            User user = existing.get();
            user.getRoles().add(superAdmin);
            user.setEnabled(true);
            log.warn("Rôle {} réattribué au compte administrateur configuré", superAdmin.getCode());
            return;
        }

        String password = admin.getPassword();
        boolean generated = password == null || password.isBlank();
        if (generated) {
            password = generatePassword();
        }
        userService.createAccount(admin.getNom(), admin.getPrenom(), email, password, List.of(superAdmin.getCode()));
        if (generated) {
            log.warn("""

                    ============================================================
                     Compte administrateur créé : {}
                     Mot de passe généré       : {}
                     Changez-le dès la première connexion (PUT /api/auth/me/password)
                     ou définissez IAM_ADMIN_PASSWORD avant le premier démarrage.
                    ============================================================""", email, password);
        } else {
            log.info("Compte administrateur créé : {}", email);
        }
    }

    private static String generatePassword() {
        final String alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789@#%&*";
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            sb.append(alphabet.charAt(random.nextInt(alphabet.length())));
        }
        return sb.toString();
    }
}
