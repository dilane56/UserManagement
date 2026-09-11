package com.cbcbourse.usermanagement.controller;


import com.cbcbourse.usermanagement.dto.AuthRequest;
import com.cbcbourse.usermanagement.dto.AuthResponse;
import com.cbcbourse.usermanagement.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody AuthRequest authRequest) {
        return ResponseEntity.ok(authService.authenticate(authRequest));
    }
}
