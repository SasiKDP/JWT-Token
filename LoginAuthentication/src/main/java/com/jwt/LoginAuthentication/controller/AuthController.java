package com.jwt.LoginAuthentication.controller;

import com.jwt.LoginAuthentication.dto.AuthResponse;
import com.jwt.LoginAuthentication.dto.LoginDTO;
import com.jwt.LoginAuthentication.dto.RegisterDTO;
import com.jwt.LoginAuthentication.dto.UserDTO;
import com.jwt.LoginAuthentication.services.AuthService;
import com.jwt.LoginAuthentication.services.JwtService;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import java.util.Date;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("users")
public class AuthController {

    private final AuthService authService;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;

    // Constructor injection
    public AuthController(AuthService authService, JwtService jwtService,
                          AuthenticationManager authenticationManager, UserDetailsService userDetailsService) {
        this.authService = authService;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
    }

    // Register a new user
    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterDTO registerDTO) {
        try {
            authService.registerUser(registerDTO);
            return ResponseEntity.ok("User registered successfully.");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error registering user: " + e.getMessage());
        }
    }

    // Login and generate JWT token (modified as per your request)
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginDTO loginDTO) {
        try {
            // Authenticate user using the AuthenticationManager
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginDTO.getEmail(), loginDTO.getPassword())
            );

            // Load user details from email after authentication
            UserDetails user = userDetailsService.loadUserByUsername(loginDTO.getEmail());

            // Generate JWT token
            String token = jwtService.generateToken(user);

            // Extract user email and expiration time from token
            String userEmail = jwtService.extractUserName(token, SignatureAlgorithm.HS256);
            Date expirationTime = jwtService.extractExpiration(token,SignatureAlgorithm.HS256);

            // Return structured response with token, email, and expiration time
            AuthResponse authResponse = new AuthResponse(token, userEmail, expirationTime);
            return ResponseEntity.ok(authResponse);

        } catch (Exception e) {
            // Return error response in case of invalid credentials or other issues
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new AuthResponse("Invalid credentials or error generating token."));
        }
    }

    // Get all registered users
    @GetMapping("/allregistered")
    public ResponseEntity<List<UserDTO>> getAllUsers() {
        try {
            List<UserDTO> users = authService.getAllUsers();
            return ResponseEntity.ok(users);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(null); // Or you could return an empty list or error response as per your requirement
        }
    }
}
