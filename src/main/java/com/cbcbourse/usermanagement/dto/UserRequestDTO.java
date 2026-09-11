package com.cbcbourse.usermanagement.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class UserRequestDTO {

    @NotBlank(message = "Le nom est obligatoire")
    private String nom;
    @NotBlank(message = "Le prénom est obligatoire")
    private String prenom;
    @NotBlank(message = "L'email est obligatoire")
    private String email;
    @NotBlank(message = "Le mot de passe est obligatoire")
    private String password;

}
