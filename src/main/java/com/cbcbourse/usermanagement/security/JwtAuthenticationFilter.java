package com.cbcbourse.usermanagement.security;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Authentifie la requête à partir du header "Authorization: Bearer ...".
 * Un token absent ou invalide n'interrompt pas la chaîne : c'est la configuration
 * d'autorisation qui décide ensuite (401 via {@link RestAuthenticationEntryPoint} si la route est protégée).
 * L'utilisateur est rechargé en base à chaque requête : un compte désactivé ou un rôle retiré
 * prend effet immédiatement, sans attendre l'expiration du token.
 */
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    public static final String AUTH_ERROR_ATTRIBUTE = "iam.auth.error";
    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;
    private final CustomUserDetailsService userDetailsService;

    /**
     * Exécuté une fois par requête : si un header "Bearer" est présent et que la requête n'est pas déjà
     * authentifiée, tente l'authentification, puis passe toujours la main au filtre suivant.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.startsWith(BEARER_PREFIX)
                && SecurityContextHolder.getContext().getAuthentication() == null) {
            authenticate(header.substring(BEARER_PREFIX.length()), request);
        }
        filterChain.doFilter(request, response);
    }

    /**
     * Valide le token, recharge l'utilisateur en base (rôles et permissions à jour) et l'enregistre
     * dans le contexte de sécurité. En cas d'échec, la raison (token expiré, invalide, compte désactivé...)
     * est mémorisée dans un attribut de la requête pour que {@link RestAuthenticationEntryPoint}
     * renvoie un message 401 précis.
     */
    private void authenticate(String token, HttpServletRequest request) {
        try {
            String email = jwtService.parse(token).getSubject();
            UserPrincipal user = userDetailsService.loadUserByUsername(email);
            if (!user.isEnabled()) {
                request.setAttribute(AUTH_ERROR_ATTRIBUTE, "Compte désactivé");
                return;
            }
            user.eraseCredentials();
            var authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (ExpiredJwtException e) {
            request.setAttribute(AUTH_ERROR_ATTRIBUTE, "Token expiré");
        } catch (JwtException | IllegalArgumentException e) {
            log.debug("Token JWT rejeté : {}", e.getMessage());
            request.setAttribute(AUTH_ERROR_ATTRIBUTE, "Token invalide");
        } catch (UsernameNotFoundException e) {
            request.setAttribute(AUTH_ERROR_ATTRIBUTE, "Utilisateur introuvable");
        }
    }
}
