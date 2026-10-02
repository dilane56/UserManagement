package com.cbcbourse.usermanagement.iam.user;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);

    /** Charge l'utilisateur avec ses rôles et permissions en une requête (authentification). */
    @Query("""
            select distinct u from User u
            left join fetch u.roles r
            left join fetch r.permissions
            where u.email = :email
            """)
    Optional<User> findWithAuthoritiesByEmail(String email);

    /** {@code term} doit être en minuscules et entouré de '%'. */
    @Query("""
            select u from User u
            where lower(u.email) like :term or lower(u.nom) like :term or lower(u.prenom) like :term
            """)
    Page<User> search(String term, Pageable pageable);

    /** Indique si au moins un utilisateur possède ce rôle (empêche la suppression d'un rôle utilisé). */
    boolean existsByRolesId(Long roleId);

    /** Nombre de comptes actifs ayant ce rôle (sert à protéger le dernier administrateur). */
    long countByRolesCodeAndEnabledTrue(String roleCode);
}
