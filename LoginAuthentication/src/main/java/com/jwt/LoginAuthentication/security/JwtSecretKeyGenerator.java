package com.jwt.LoginAuthentication.security;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;

public class JwtSecretKeyGenerator {

    public static void main(String[] args) {
        // Generate a 256-bit (32-byte) secret key for HS256
        Key secretKey = generateSecretKeyForHS256();

        // Print the Base64-encoded secret key
        System.out.println("Generated Secret Key (Base64): " + Base64.getEncoder().encodeToString(secretKey.getEncoded()));
    }

    public static Key generateSecretKeyForHS256() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] keyBytes = new byte[32];  // 256-bit key for HS256
        secureRandom.nextBytes(keyBytes);
        return new javax.crypto.spec.SecretKeySpec(keyBytes, "HmacSHA256");
    }
}
