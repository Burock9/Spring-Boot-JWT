package com.burock.jwt.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class TestController {

    @GetMapping("/public")
    public String publicEndpoint() { return "This is public"; }

    @GetMapping("/user")
    public String userEndpoint(@AuthenticationPrincipal UserDetails ud) {
        return "Hello USER: " + ud.getUsername();
    }

    @GetMapping("/admin")
    public String adminEndpoint(@AuthenticationPrincipal UserDetails ud) {
        return "Hello ADMIN: " + ud.getUsername();
    }

    @GetMapping("/profile")
    public Object profile(@AuthenticationPrincipal UserDetails ud) {
        return ud;
    }
}
