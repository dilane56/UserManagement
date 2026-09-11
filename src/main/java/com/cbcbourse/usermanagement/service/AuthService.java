package com.cbcbourse.usermanagement.service;

import com.cbcbourse.usermanagement.dto.AuthRequest;
import com.cbcbourse.usermanagement.dto.AuthResponse;
import com.cbcbourse.usermanagement.exception.ResourceNotFoundException;
import com.cbcbourse.usermanagement.mapper.UserMapper;
import com.cbcbourse.usermanagement.model.User;
import com.cbcbourse.usermanagement.repository.UserRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    @Value("${jwt.secret}")
    private String jwtSecret; // Inject the JWT secret from application.properties

    @Value("${jwt.expiration}")
    private long jwtExpiration; // Inject the JWT expiration time from application.properties

    private SecretKey secretKey; // Secret key for signing JWTs

    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final UserRepository userRepository;
    private final UserMapper userMapper;
    //private final JwtUtils jwtUtils;
    // Initialisation de la clé au démarrage du service
    // @PostConstruct est une bonne pratique pour l'initialisation après l'injection de dépendances
    @jakarta.annotation.PostConstruct // Utilisez jakarta.annotation.PostConstruct si Spring Boot 3+
    private void init() {
        // Décoder la chaîne Base64 en bytes, puis créer la SecretKey
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        this.secretKey = Keys.hmacShaKeyFor(keyBytes);
        log.info("Clé JWT initialisée avec succès.");

    }


   public AuthResponse authenticate(@Valid AuthRequest authRequest) {
        // Ne jamais logger l'email ou le mot de passe (données sensibles / PII)
        log.info("Tentative de connexion en cours...");
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authRequest.getEmail(), authRequest.getPassword())
        );
        User user = userRepository.findByEmail(authRequest.getEmail()).orElseThrow(() -> new ResourceNotFoundException("user not found"));
        UserDetails userDetails = userDetailsService.loadUserByUsername(authRequest.getEmail());
        log.info("Authentification réussie.");
        String token = Jwts.builder()
                .subject(userDetails.getUsername())
                .issuedAt(new java.util.Date(System.currentTimeMillis()))
                .expiration(new java.util.Date(System.currentTimeMillis() + jwtExpiration))
                .signWith(secretKey)
                .compact();

        AuthResponse authResponse = new AuthResponse();
        authResponse.setToken(token);
        authResponse.setUser(userMapper.userToUserResponseDTO(user));
        return authResponse;
    }







}
