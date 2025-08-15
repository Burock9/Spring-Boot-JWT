package com.burock.jwt.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import com.burock.jwt.dto.LoginRequest;
import com.burock.jwt.dto.RegisterRequest;
import com.burock.jwt.model.User;
import com.burock.jwt.security.JwtUtil;
import com.burock.jwt.service.UserService;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService userService;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;

    public AuthController(UserService userService, JwtUtil jwtUtil, AuthenticationManager authenticationManager) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest registerDTO) {
        String role = (registerDTO.getRole() != null && !registerDTO.getRole().isBlank())
                ? registerDTO.getRole()
                : "ROLE_USER";

        User u = userService.register(registerDTO.getUsername(), registerDTO.getPassword(), role);
        return ResponseEntity.ok(Map.of(
                "id", u.getId(),
                "username", u.getUsername(),
                "role", u.getRole()));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginDTO) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginDTO.getUsername(),
                            loginDTO.getPassword()));

            var userDetails = (org.springframework.security.core.userdetails.User) authentication.getPrincipal();
            String role = userDetails.getAuthorities().iterator().next().getAuthority();

            String token = jwtUtil.generateToken(userDetails.getUsername(), role);
            return ResponseEntity.ok(Map.of("token", token));

        } catch (BadCredentialsException ex) {
            return ResponseEntity.status(401).body(Map.of("error", "Geçersiz kimlik bilgileri"));
        }
    }
}
