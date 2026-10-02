package com.cbcbourse.usermanagement.common.exception;

import org.springframework.http.HttpStatus;

public class ResourceNotFoundException extends ApiException {

    public ResourceNotFoundException(String message) {
        super(HttpStatus.NOT_FOUND, message);
    }

    /** Fabrique un message uniforme, ex : {@code of("Utilisateur", 42)} donne "Utilisateur introuvable : 42". */
    public static ResourceNotFoundException of(String resource, Object identifier) {
        return new ResourceNotFoundException(resource + " introuvable : " + identifier);
    }
}
