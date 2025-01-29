package com.jwt.LoginAuthentication.model;

import jakarta.persistence.*;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Entity
@Data
public class UserDetail implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String email;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getRoles() {
        return roles;
    }

    public void setRoles(String roles) {
        this.roles = roles;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String name;

    private String roles = "ROLE_USER"; // Default role

    private String token; // Add this field to store the token

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(() -> roles); // Convert roles into GrantedAuthority
    }


    @Override
    public String getUsername() {
        return this.email;  // Return the email explicitly as username
    }


    @Override
    public boolean isAccountNonExpired() {
        return true;  // You can modify these based on your business logic
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;  // Similarly modify based on business logic
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;  // Modify as needed
    }

    @Override
    public boolean isEnabled() {
        return true;  // Modify if you want to enable/disable user functionality
    }
}
