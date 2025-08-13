package com.burock.jwt.service;

import java.util.Collections;
import java.util.Optional;

import com.burock.jwt.model.User;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.burock.jwt.repository.UserRepository;

@Service
public class UserService implements UserDetailsService {

    private final UserRepository repo;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository repo, PasswordEncoder passwordEncoder) {
        this.repo = repo;
        this.passwordEncoder = passwordEncoder;
    }

    public PasswordEncoder passwordEncoder() { return this.passwordEncoder; }

    public User register(String username, String rawPassword, String role) {
        if (repo.findByUsername(username).isPresent()) {
            throw new RuntimeException("Kullanıcı zaten var");
        }
        User u = new User(username, passwordEncoder.encode(rawPassword), role);
        return repo.save(u);
    }

    public Optional<User> findByUsername(String username) {
        return repo.findByUsername(username);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User u = repo.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return new org.springframework.security.core.userdetails.User(
                u.getUsername(),
                u.getPassword(),
                Collections.singletonList(new SimpleGrantedAuthority(u.getRole())));
    }
}