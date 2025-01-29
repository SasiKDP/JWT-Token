package com.jwt.LoginAuthentication.security;

import io.jsonwebtoken.SignatureAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import com.jwt.LoginAuthentication.services.JwtService;
import com.jwt.LoginAuthentication.dao.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtService jwtService; // Inject JwtService

    @Autowired
    private UserDetailsService userDetailsService; // Inject UserDetailsService

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        log.info("==== Auth Header: {} ====", authHeader);

        // If no Bearer token, move to the next filter
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.info("==== No Bearer token found ====");
            filterChain.doFilter(request, response);
            return;
        }

        // Extract the JWT token from the Authorization header
        String jwt = authHeader.substring(7);
        log.info("==== JWT Token: {} ====", jwt);

        try {
            // Extract the email (subject) from the token
            String userEmail = jwtService.extractUserName(jwt, SignatureAlgorithm.HS256);  // Defaulting to HS256 here
            log.info("==== Extracted email from token: {} ====", userEmail);

            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                // Load user details from the database by email
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
                log.info("==== User details loaded: {} ====", userDetails.getUsername());

                // Validate if the token is still valid for the user
                if (jwtService.isTokenValid(jwt, userDetails, SignatureAlgorithm.HS256)) {  // Defaulting to HS256 here
                    log.info("==== Token is valid, setting authentication ====");

                    // Set the authentication in the security context
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                } else {
                    log.error("==== Token is invalid or expired ====");
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);  // Send 401 Unauthorized response
                }
            }
        } catch (Exception e) {
            log.error("==== Error processing JWT token: {} ====", e.getMessage());
            if (e instanceof io.jsonwebtoken.SignatureException) {
                log.error("==== JWT signature verification failed ====");
            } else if (e instanceof io.jsonwebtoken.ExpiredJwtException) {
                log.error("==== JWT token expired ====");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);  // Send 401 Unauthorized response
            } else {
                log.error("==== General error: {} ====", e.getMessage());
            }
        }

        // Proceed to the next filter in the chain
        filterChain.doFilter(request, response);
    }
}
