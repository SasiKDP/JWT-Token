package com.jwt.LoginAuthentication.dto;

import lombok.AllArgsConstructor;

@AllArgsConstructor
public class UserDTO {

    private String email;
    private String token;

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
// You can add more fields as needed (e.g., roles, status, etc.)
}
