package com.cbcbourse.usermanagement.common.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

/**
 * Exception métier portant son statut HTTP.
 * Les modules peuvent l'utiliser directement ou via les sous-classes spécialisées.
 */
@Getter
public class ApiException extends RuntimeException {

    private final HttpStatus status;

    public ApiException(HttpStatus status, String message) {
        super(message);
        this.status = status;
    }
}
