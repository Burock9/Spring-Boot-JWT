package com.burock.jwt.dto;

import lombok.*;

@Data
public class RegisterRequest {

    private String username;
    private String password;
    private String role;
}
