package com.cbcbourse.usermanagement.dto;

import lombok.Data;

@Data
public class UserResponseDTO {
    private Long id;
    private String nom;
    private String prenom;
    private String email;
    private String role;
}
