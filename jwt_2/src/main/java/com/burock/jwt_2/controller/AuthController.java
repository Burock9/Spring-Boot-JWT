package com.burock.jwt_2.controller;

import java.security.Principal;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.burock.jwt_2.dto.LoginRequest;
import com.burock.jwt_2.dto.TokenResponse;
import com.burock.jwt_2.model.Role;
import com.burock.jwt_2.model.User;
import com.burock.jwt_2.service.JwtService;
import com.burock.jwt_2.service.UserService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authManager;
    private final JwtService jwtService;
    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody LoginRequest req) {
        if (userService.exists(req.getUsername())) {
            return ResponseEntity.badRequest().body("Kullanıcı adı zaten var.");
        }
        User u = User.builder().username(req.getUsername()).password(userService.encode(req.getPassword()))
                .roles(Set.of(Role.ROLE_USER)).build();
        userService.save(u);
        return ResponseEntity.ok("Kayıtlı");
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest req) {
        Authentication auth = authManager.authenticate(new UsernamePasswordAuthenticationToken(req.getUsername(), req.getPassword()));
        var roles = auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
        String token = jwtService.generateToken(req.getUsername(), roles);
        return ResponseEntity.ok(TokenResponse.builder().token(token).build());
    }

    @GetMapping("/me")
    public ResponseEntity<User> me(Principal principal) {
        User u = userService.getByUsernameSecured(principal.getName());
        return ResponseEntity.ok(u);
    }
}
