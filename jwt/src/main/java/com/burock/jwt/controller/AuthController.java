package com.burock.jwt.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.burock.jwt.model.User;
import com.burock.jwt.security.JwtUtil;
import com.burock.jwt.service.UserService;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService userService;
    private final JwtUtil jwtUtil;

    public AuthController(UserService userService, JwtUtil jwtUtil) {
        this.userService = userService; this.jwtUtil = jwtUtil;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String,String> body) {
        String username = body.get("username");
        String password = body.get("password");
        String role = body.getOrDefault("role", "ROLE_USER"); 

        User u = userService.register(username, password, role);
        return ResponseEntity.ok(Map.of("id", u.getId(), "username", u.getUsername(), "role", u.getRole()));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String,String> body) {
        String username = body.get("username");
        String password = body.get("password");

        // authenticate using AuthenticationManager via provider
        try {
            // load user
            var userOpt = userService.findByUsername(username).orElseThrow();
            // check password (we could use manager but direct check ok here)
            if (!userService.passwordEncoder().matches(password, userOpt.getPassword())) {
                return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
            }

            String token = jwtUtil.generateToken(username, userOpt.getRole());
            return ResponseEntity.ok(Map.of("token", token));
        } catch (Exception ex) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
        }
    }
}
