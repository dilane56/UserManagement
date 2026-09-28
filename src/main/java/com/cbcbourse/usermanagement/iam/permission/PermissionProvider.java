package com.cbcbourse.usermanagement.iam.permission;

import java.util.Collection;

/**
 * Point d'extension : chaque module métier déclare ses permissions en exposant un bean
 * qui implémente cette interface. Elles sont synchronisées en base au démarrage.
 *
 * <pre>
 * &#64;Component
 * public class PortfolioPermissions implements PermissionProvider {
 *     public static final String PORTFOLIO_READ = "PORTFOLIO_READ";
 *
 *     &#64;Override
 *     public Collection&lt;PermissionDefinition&gt; permissions() {
 *         return List.of(new PermissionDefinition(PORTFOLIO_READ, "Consulter les portefeuilles", "PORTFOLIO"));
 *     }
 * }
 * </pre>
 */
public interface PermissionProvider {

    Collection<PermissionDefinition> permissions();
}
