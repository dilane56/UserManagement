package com.cbcbourse.usermanagement.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    /** Routes publiques du socle. Les modules ajoutent les leurs via iam.security.public-paths. */
    private static final List<String> DEFAULT_PUBLIC_PATHS = List.of(
            "/api/auth/login",
            "/api/auth/refresh",
            "/api/auth/logout",
            "/api/auth/register",
            "/v3/api-docs/**",
            "/swagger-ui/**",
            "/swagger-ui.html",
            "/error"
    );

    private final IamProperties iamProperties;
    private final RestAuthenticationEntryPoint restAuthenticationEntryPoint;

    /**
     * Encodeur des mots de passe. Délégant ({bcrypt} par défaut) : chaque hash porte le nom de son algorithme,
     * ce qui permet de changer d'algorithme plus tard sans casser les mots de passe existants.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * Gestionnaire utilisé par le login : charge l'utilisateur par email, compare le mot de passe
     * et refuse les comptes désactivés (DisabledException).
     */
    @Bean
    public AuthenticationManager authenticationManager(CustomUserDetailsService userDetailsService,
                                                       PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return new ProviderManager(provider);
    }

    /**
     * Chaîne de sécurité HTTP : API sans état (pas de session), CORS, routes publiques, toutes les autres
     * routes authentifiées, réponses 401/403 en JSON et filtre JWT placé avant l'authentification standard.
     * Le contrôle fin des droits se fait ensuite sur chaque endpoint avec {@code @PreAuthorize}.
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, JwtService jwtService,
                                           CustomUserDetailsService userDetailsService) throws Exception {
        List<String> publicPaths = new ArrayList<>(DEFAULT_PUBLIC_PATHS);
        publicPaths.addAll(iamProperties.getSecurity().getPublicPaths());

        return http
                // CSRF désactivé intentionnellement : API REST stateless authentifiée par JWT (aucun cookie de session).
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(publicPaths.toArray(String[]::new)).permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(restAuthenticationEntryPoint)
                        .accessDeniedHandler(restAuthenticationEntryPoint))
                .addFilterBefore(new JwtAuthenticationFilter(jwtService, userDetailsService),
                        UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    /** Règles CORS (origines, méthodes, headers autorisés) lues dans iam.cors.*, appliquées à toutes les routes. */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        IamProperties.Cors props = iamProperties.getCors();
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(props.getAllowedOrigins());
        configuration.setAllowedMethods(props.getAllowedMethods());
        configuration.setAllowedHeaders(props.getAllowedHeaders());
        configuration.setAllowCredentials(props.isAllowCredentials());
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
