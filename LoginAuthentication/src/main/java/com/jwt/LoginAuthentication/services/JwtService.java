package com.jwt.LoginAuthentication.services;

import com.jwt.LoginAuthentication.dao.UserRepository;
import com.jwt.LoginAuthentication.model.UserDetail;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.Base64;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String jwtSecret;

    private static final long JWT_TOKEN_VALIDITY = 30 * 60 * 1000; // 30 minutes in milliseconds

    private final UserRepository userRepository;

    public JwtService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public Key getSignInKey(SignatureAlgorithm algorithm) {
        byte[] keyBytes = Base64.getDecoder().decode(jwtSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails, SignatureAlgorithm.HS256);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails, SignatureAlgorithm algorithm) {
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY))
                .signWith(getSignInKey(algorithm), algorithm)
                .compact();
    }

    public Claims extractAllClaims(String token, SignatureAlgorithm algorithm) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getSignInKey(algorithm))
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            throw new JwtException("JWT token has expired");
        } catch (UnsupportedJwtException e) {
            throw new JwtException("Unsupported JWT token");
        } catch (MalformedJwtException e) {
            throw new JwtException("Invalid JWT token");
        } catch (SignatureException e) {
            throw new JwtException("Invalid JWT signature");
        } catch (Exception e) {
            throw new JwtException("JWT token error: " + e.getMessage());
        }
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver, SignatureAlgorithm algorithm) {
        final Claims claims = extractAllClaims(token, algorithm);
        return claimsResolver.apply(claims);
    }

    public String extractUserName(String token, SignatureAlgorithm algorithm) {
        return extractClaim(token, Claims::getSubject, algorithm);
    }

    public Date extractExpiration(String token, SignatureAlgorithm algorithm) {
        return extractClaim(token, Claims::getExpiration, algorithm);
    }

    private boolean isTokenExpired(String token, SignatureAlgorithm algorithm) {
        return extractExpiration(token, algorithm).before(new Date());
    }

    public boolean isTokenValid(String token, UserDetails userDetails, SignatureAlgorithm algorithm) {
        final String email = userDetails.getUsername();
        return (email.equals(extractUserName(token, algorithm)) && !isTokenExpired(token, algorithm));
    }

    public void storeTokenInDatabase(UserDetails userDetails, String token) {
        UserDetail userDetail = userRepository.findByEmail(userDetails.getUsername());
        if (userDetail != null) {
            userDetail.setToken(token);
            userRepository.save(userDetail);
        }
    }
}