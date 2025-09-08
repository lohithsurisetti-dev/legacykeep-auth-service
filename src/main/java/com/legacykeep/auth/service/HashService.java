package com.legacykeep.auth.service;

/**
 * Service for generating and managing hashes for encrypted field searches.
 * 
 * This service provides methods to generate consistent hashes for email and username
 * fields to enable efficient database searches while maintaining data encryption.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
public interface HashService {
    
    /**
     * Generate a hash for email address.
     * 
     * @param email The email address to hash
     * @return The hash value
     */
    String generateEmailHash(String email);
    
    /**
     * Generate a hash for username.
     * 
     * @param username The username to hash
     * @return The hash value
     */
    String generateUsernameHash(String username);
    
    /**
     * Generate a hash for phone number.
     * 
     * @param phoneNumber The phone number to hash
     * @return The hash value
     */
    String generatePhoneHash(String phoneNumber);
    
    /**
     * Verify if a hash matches the given value.
     * 
     * @param value The original value
     * @param hash The hash to verify
     * @return True if the hash matches the value
     */
    boolean verifyHash(String value, String hash);
}
