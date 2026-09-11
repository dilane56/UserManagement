package com.cbcbourse.usermanagement.service;


import com.cbcbourse.usermanagement.dto.UserRequestDTO;
import com.cbcbourse.usermanagement.exception.ResourceNotFoundException;
import com.cbcbourse.usermanagement.exception.EmailAlreadyUsedException;
import com.cbcbourse.usermanagement.mapper.UserMapper;
import com.cbcbourse.usermanagement.model.User;
import com.cbcbourse.usermanagement.repository.UserRepository;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;

    public User createUser(@Valid UserRequestDTO userRequestDTO){
        // Vérifier si un utilisateur avec cetemail existe déjà
        if (userRepository.findByEmail(userRequestDTO.getEmail()).isPresent()) {
            throw new EmailAlreadyUsedException();
        }

        // Mapper le DTO en entité User
        User user = userMapper.userResquestDTOToUser(userRequestDTO);

        // Encoder le mot de passe avant de sauvegarder
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRole("USER"); // Définir le rôle par défaut

        return userRepository.save(user);
    }

    public User getUserById(Long id) {
        return userRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + id));
    }

    public void deleteUser(Long id) {
        if(!userRepository.existsById(id)) {
            throw new ResourceNotFoundException("User not found with id: " + id);
        }
        userRepository.deleteById(id);
    }

    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    public User getUserByEmail(String email) {
        return userRepository.findByEmail(email).orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));
    }

    public User updateUser(Long id,@Valid UserRequestDTO userRequestDTO) {
        User existingUser = userRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + id));

        // Vérifier si l'email est modifié et s'il est déjà utilisé par un autre utilisateur
        if (!existingUser.getEmail().equals(userRequestDTO.getEmail()) && userRepository.findByEmail(userRequestDTO.getEmail()).isPresent()) {
            throw new EmailAlreadyUsedException();
        }

        // Mettre à jour les champs de l'utilisateur existant
        existingUser.setEmail(userRequestDTO.getEmail());
        existingUser.setNom(userRequestDTO.getNom());
        existingUser.setRole("USER");

        // Si le mot de passe est fourni, l'encoder avant de le mettre à jour
        if (userRequestDTO.getPassword() != null && !userRequestDTO.getPassword().isEmpty()) {
            existingUser.setPassword(passwordEncoder.encode(userRequestDTO.getPassword()));
        }

        return userRepository.save(existingUser);
    }

}
