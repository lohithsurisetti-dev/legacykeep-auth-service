package com.legacykeep.auth.service;

import com.legacykeep.auth.dto.EncryptionStatistics;

/**
 * Data Encryption Service for handling encryption of existing sensitive data.
 * 
 * This service provides methods to encrypt existing plain text data
 * in the database and ensure all sensitive information is properly protected.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
public interface DataEncryptionService {

    /**
     * Encrypt all existing sensitive data in the database.
     * This method should be called during application startup to ensure
     * all existing data is properly encrypted.
     */
    void encryptExistingData();

    /**
     * Encrypt existing user data (emails, usernames).
     */
    void encryptExistingUserData();

    /**
     * Encrypt existing session data (IP addresses, locations).
     */
    void encryptExistingSessionData();

    /**
     * Encrypt existing audit log data (IP addresses).
     */
    void encryptExistingAuditData();

    /**
     * Verify that all sensitive data is properly encrypted.
     * 
     * @return true if all data is encrypted, false otherwise
     */
    boolean verifyDataEncryption();

    /**
     * Get encryption statistics.
     * 
     * @return encryption statistics information
     */
    EncryptionStatistics getEncryptionStatistics();

    /**
     * Populate hash values for encryption.
     * This method should be called to initialize hash values
     * that are used for encryption and decryption.
     */
    void populateHashValues();
}
