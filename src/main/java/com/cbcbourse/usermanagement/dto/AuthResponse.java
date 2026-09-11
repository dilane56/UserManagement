package com.cbcbourse.usermanagement.dto;

import lombok.Data;

@Data
public class AuthResponse {
    private String token;
   private UserResponseDTO user;
}
