package com.cbcbourse.usermanagement.iam.permission;

/** Déclaration d'une permission par un module (voir {@link PermissionProvider}). */
public record PermissionDefinition(String code, String description, String module) {
}
