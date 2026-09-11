package com.cbcbourse.usermanagement.config;

import lombok.extern.slf4j.Slf4j;
import com.cbcbourse.usermanagement.service.CustomUserDetailsService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.util.Base64;

@Slf4j
@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    @Value("${jwt.secret}")
    private String secretKey;// Injection de la cle secrete depuis le fichier application.properties

    private SecretKey signingKey; // pour stocker la clé de signature dérivée de la clé secrète

    private final CustomUserDetailsService userDetailsService;

    public JwtRequestFilter(CustomUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    // Initialisation de la clé au demarrage du filtre
    @PostConstruct
    private void init() {
        try {
            //Décoder la chaine Base64 en bytes, puis créer la clé de signature
            byte[] keyBytes = Base64.getDecoder().decode(secretKey);
            this.signingKey = Keys.hmacShaKeyFor(keyBytes);
            log.info("Clé JWT initialisée avec succès dans JwtRequestFilter.");
        } catch (IllegalArgumentException e) {
            log.info("Erreur lors du décodage de la clé JWT. Assurez-vous que 'jwt.secret' est une chaîne Base64 valide.");
            throw new RuntimeException("Impossible d'initialiser la clé JWT.", e);
        }
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // Implement JWT validation logic here
        final String authorizationHeader = request.getHeader("Authorization");

        String jwt = null;
        String username = null;
        String path = request.getRequestURI();
        // Ignorer les endpoints publics (ex: /api/auth/login, /api/auth/register)
        if (path.startsWith("/api/auth/")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            // Extraire le token s'il existe
            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                jwt = authorizationHeader.substring(7);
                //utiliser la cle secrete initialisée dans ce filtre
                Claims claims = Jwts.parser()
                        .verifyWith(this.signingKey)
                        .build()
                        .parseSignedClaims(jwt)
                        .getPayload();

                username = claims.getSubject();
                log.info("Token JWT decodé avec succès. Utilisateur: {}", sanitize(username));
            }

            //Authentifier le token est valide et que l'utilisateur n'est pas deja authentifier
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                // Charger les details de l'utilisateur
                var userDetails = userDetailsService.loadUserByUsername(username);
                // Ici, vous pouvez ajouter la logique pour vérifier si le token est valide par rapport aux détails de l'utilisateur
                // Par exemple, vérifier si le token n'est pas expiré, etc.
                // Si tout est bon, vous pouvez définir l'authentification dans le contexte de sécurité
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                log.info("Utilisateur authentifié avec succès: {}", sanitize(username));
            }

            // laiser la requête continuer vers le prochain filtre de la chaine
            filterChain.doFilter(request, response);
        } catch (SignatureException e) {
            log.warn("Signature JWT invalide.", e);
            sendUnauthorizedResponse(response, "Signature du token invalide.");
        } catch (io.jsonwebtoken.ExpiredJwtException e) {
            log.warn("Token JWT expiré.", e);
            sendUnauthorizedResponse(response, "Token expiré.");
        } catch (io.jsonwebtoken.MalformedJwtException e) {
            log.warn("Token JWT malformé.", e);
            sendUnauthorizedResponse(response, "Token malformé.");
        } catch (io.jsonwebtoken.JwtException e) {
            log.warn("Token JWT invalide.", e);
            sendUnauthorizedResponse(response, "Token invalide.");
        } catch (org.springframework.security.core.userdetails.UsernameNotFoundException e) {
            log.warn("Utilisateur introuvable lors de la validation du token.", e);
            sendUnauthorizedResponse(response, "Utilisateur introuvable.");
        }
    }


    private String sanitize(String input) {
        if (input == null) return "null";
        return input.replaceAll("[\r\n\t]", "_");
    }

    private void sendUnauthorizedResponse(HttpServletResponse response, String message) throws IOException {
        if (!response.isCommitted()) {
            response.resetBuffer();
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"" + message + "\"}");
        }
    }


}
