package com.cbcbourse.usermanagement.service;

import com.cbcbourse.usermanagement.exception.ResourceNotFoundException;
import com.cbcbourse.usermanagement.model.User;
import com.cbcbourse.usermanagement.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = userRepository.findByEmail(username).orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + username));

        return new org.springframework.security.core.userdetails.User(user.getEmail(),user.getPassword(),getGrantedAuthorities(user.getRole()));
    }

    private List<GrantedAuthority> getGrantedAuthorities(String role){
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE_"+ role));
        return  authorities;
    }
}
