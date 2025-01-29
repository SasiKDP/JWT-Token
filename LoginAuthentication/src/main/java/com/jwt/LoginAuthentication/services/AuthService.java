package com.jwt.LoginAuthentication.services;

import com.jwt.LoginAuthentication.dao.UserRepository;
import com.jwt.LoginAuthentication.dto.LoginDTO;
import com.jwt.LoginAuthentication.dto.RegisterDTO;
import com.jwt.LoginAuthentication.dto.UserDTO;
import com.jwt.LoginAuthentication.model.UserDetail;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService, AuthenticationManager authenticationManager) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }

    public Map<String, String> loginUser(LoginDTO loginDTO) {
        try {
            // Authenticate the user credentials using AuthenticationManager
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginDTO.getEmail(), loginDTO.getPassword())
            );

            // Load user details from the database
            UserDetails userDetails = userRepository.findByEmail(loginDTO.getEmail());

            // If user details are not found, throw an exception
            if (userDetails == null) {
                throw new RuntimeException("User not found with email: " + loginDTO.getEmail());
            }

            // Generate JWT Token using user details (HS256 is default)
            String token = jwtService.generateToken(userDetails);

            // Prepare the response with the JWT token
            Map<String, String> response = new HashMap<>();
            response.put("token", token);

            return response;
        } catch (BadCredentialsException e) {
            // Handle invalid credentials exception (e.g., wrong password)
            throw new RuntimeException("Invalid credentials: The provided password is incorrect.");
        } catch (Exception e) {
            // Handle other exceptions (e.g., user not found, JWT token generation error)
            throw new RuntimeException("Error during login: " + e.getMessage());
        }
    }

    // Register user with encrypted password
    public void registerUser(RegisterDTO registerDTO) {
        if (userRepository.existsByEmail(registerDTO.getEmail())) {
            throw new RuntimeException("Email already registered");
        }

        UserDetail user = new UserDetail();
        user.setName(registerDTO.getName());
        user.setEmail(registerDTO.getEmail());
        user.setPassword(passwordEncoder.encode(registerDTO.getPassword())); // Encrypt the password
        userRepository.save(user);
    }

    // Validate if a JWT token is valid
    public boolean validateToken(String token, UserDetails userDetails) {
        try {
            // Validates the token by checking the userDetails and the JWT
            return jwtService.isTokenValid(token, userDetails, SignatureAlgorithm.HS256);  // Default algorithm is HS256
        } catch (ExpiredJwtException e) {
            // Handle expired token case
            throw new RuntimeException("JWT token has expired.");
        } catch (MalformedJwtException e) {
            // Handle malformed JWT token case (incorrect format)
            throw new RuntimeException("JWT token is malformed.");
        } catch (JwtException e) {
            // General case for all other JWT-related exceptions
            throw new RuntimeException("Invalid JWT token: " + e.getMessage());
        } catch (Exception e) {
            // Fallback catch block for unexpected exceptions
            throw new RuntimeException("Error during token validation: " + e.getMessage());
        }
    }

    // Get all users (with mapping to UserDTO)
    public List<UserDTO> getAllUsers() {
        List<UserDetail> users = userRepository.findAll();
        return users.stream()
                .map(user -> new UserDTO(user.getToken(), user.getEmail()))  // Convert to UserDTO
                .collect(Collectors.toList());
    }
}
