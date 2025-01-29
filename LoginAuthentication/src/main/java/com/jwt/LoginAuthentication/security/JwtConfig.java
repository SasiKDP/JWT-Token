package com.jwt.LoginAuthentication.security;

import com.jwt.LoginAuthentication.dao.UserRepository;
import com.jwt.LoginAuthentication.services.JwtService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtConfig {

    private final UserRepository userRepository;

    // Constructor injection for UserRepository
    public JwtConfig(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Bean
    public JwtService jwtService() {
        // Now JwtService is properly injected with UserRepository
        return new JwtService(userRepository);
    }
}
