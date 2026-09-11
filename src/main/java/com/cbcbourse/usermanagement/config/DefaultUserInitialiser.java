package com.cbcbourse.usermanagement.config;

import com.cbcbourse.usermanagement.model.User;
import com.cbcbourse.usermanagement.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class DefaultUserInitialiser implements CommandLineRunner {

   private final UserRepository userRepository;
   private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        // verifier si l'utilisateur existe deja
        if(userRepository.findByEmail("admin@gmail.com").isEmpty()){
            User user = new User();
            user.setNom("Admin");
            user.setRole("Admin");
            user.setEmail("admin@gmail.com");
            user.setPassword(passwordEncoder.encode("password"));

            userRepository.save(user);
        }

    }
}
