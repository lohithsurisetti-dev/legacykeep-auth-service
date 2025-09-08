package com.legacykeep.auth.service.impl;

import com.legacykeep.auth.service.HashService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Implementation of HashService for generating consistent hashes.
 * 
 * Uses SHA-256 for generating hashes of email and username fields
 * to enable efficient database searches while maintaining data encryption.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Slf4j
@Service
public class HashServiceImpl implements HashService {

    @Value("${auth.encryption.secret-key:default-secret-key}")
    private String secretKey;

    @Override
    public String generateEmailHash(String email) {
        if (email == null || email.trim().isEmpty()) {
            throw new IllegalArgumentException("Email cannot be null or empty");
        }
        
        // Normalize email to lowercase for consistent hashing
        String normalizedEmail = email.toLowerCase().trim();
        return generateHash(normalizedEmail + "|email|" + secretKey);
    }

    @Override
    public String generateUsernameHash(String username) {
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("Username cannot be null or empty");
        }
        
        // Normalize username to lowercase for consistent hashing
        String normalizedUsername = username.toLowerCase().trim();
        return generateHash(normalizedUsername + "|username|" + secretKey);
    }

    @Override
    public String generatePhoneHash(String phoneNumber) {
        if (phoneNumber == null || phoneNumber.trim().isEmpty()) {
            throw new IllegalArgumentException("Phone number cannot be null or empty");
        }
        
        // Normalize phone number by removing spaces and special characters for consistent hashing
        String normalizedPhone = phoneNumber.replaceAll("[\\s\\-\\(\\)]", "").trim();
        return generateHash(normalizedPhone + "|phone|" + secretKey);
    }

    @Override
    public boolean verifyHash(String value, String hash) {
        if (value == null || hash == null) {
            return false;
        }
        
        try {
            String generatedHash = generateHash(value + "|" + secretKey);
            return generatedHash.equals(hash);
        } catch (Exception e) {
            log.error("Error verifying hash: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * Generate SHA-256 hash of the input string.
     */
    private String generateHash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            
            // Convert to hexadecimal string
            StringBuilder hexString = new StringBuilder();
            for (byte hashByte : hashBytes) {
                String hex = Integer.toHexString(0xff & hashByte);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            log.error("SHA-256 algorithm not available: {}", e.getMessage(), e);
            throw new RuntimeException("Hash generation failed", e);
        }
    }
}
