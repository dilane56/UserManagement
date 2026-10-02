package com.cbcbourse.usermanagement.security;

import com.cbcbourse.usermanagement.common.exception.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/** Réponses JSON 401 / 403 produites par la chaîne de filtres de sécurité (même format que l'API). */
@Component
@RequiredArgsConstructor
public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint, AccessDeniedHandler {

    private final ObjectMapper objectMapper;

    /**
     * Appelée quand une route protégée est atteinte sans authentification valide (401).
     * Le message précise la cause détectée par le filtre JWT (token expiré, invalide...) quand elle est connue.
     */
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException {
        Object detail = request.getAttribute(JwtAuthenticationFilter.AUTH_ERROR_ATTRIBUTE);
        write(response, request, HttpStatus.UNAUTHORIZED, detail != null ? detail.toString() : "Authentification requise");
    }

    /** Appelée quand l'utilisateur est authentifié mais n'a pas les droits requis par la route (403). */
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException)
            throws IOException {
        write(response, request, HttpStatus.FORBIDDEN, "Accès refusé");
    }

    /** Écrit une {@link ErrorResponse} JSON, sauf si la réponse a déjà commencé à être envoyée. */
    private void write(HttpServletResponse response, HttpServletRequest request, HttpStatus status, String message)
            throws IOException {
        if (response.isCommitted()) {
            return;
        }
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        objectMapper.writeValue(response.getOutputStream(),
                ErrorResponse.of(status.value(), status.getReasonPhrase(), message, request.getRequestURI()));
    }
}
