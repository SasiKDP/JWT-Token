package com.jwt.LoginAuthentication.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AuthResponse {
    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Date getExpirationDate() {
        return expirationDate;
    }

    public void setExpirationDate(Date expirationDate) {
        this.expirationDate = expirationDate;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    private String token;
    private String email;
    private Date expirationDate;
    private String errorMessage;    // Error message in case of failure


    // Constructor for success response (with token, email, and expiration date)
    public AuthResponse(String token, String email, Date expirationDate) {
        this.token = token;
        this.email = email;
        this.expirationDate = expirationDate;
    }

    // Constructor for error response (with error message)
    public AuthResponse(String errorMessage) {
        this.errorMessage = errorMessage;
    }
}
