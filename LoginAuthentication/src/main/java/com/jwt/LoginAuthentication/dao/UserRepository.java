package com.jwt.LoginAuthentication.dao;

import com.jwt.LoginAuthentication.model.UserDetail;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserDetail, Long> {

    // This method will retrieve a user by their email
    UserDetail findByEmail(String email);

    // This method will check if a user with the given email exists in the database
    boolean existsByEmail(String email);
}
