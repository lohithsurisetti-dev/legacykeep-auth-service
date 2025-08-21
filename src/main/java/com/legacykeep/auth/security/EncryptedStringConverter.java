package com.legacykeep.auth.security;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

/**
 * JPA Attribute Converter for encrypting sensitive string fields in the database.
 * 
 * This converter automatically encrypts/decrypts sensitive data like tokens,
 * secrets, and personal identifiers before storing them in the database.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Converter
@Component
public class EncryptedStringConverter implements AttributeConverter<String, String> {

    @Value("${auth.encryption.secret-key:default-encryption-key-change-in-production}")
    private String secretKey;

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";

    /**
     * Converts a plain text string to an encrypted string for database storage.
     * 
     * @param plainText the plain text string to encrypt
     * @return the encrypted string, or null if input is null
     */
    @Override
    public String convertToDatabaseColumn(String plainText) {
        if (plainText == null || plainText.trim().isEmpty()) {
            return null;
        }
        
        try {
            SecretKeySpec secretKeySpec = generateKey();
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting sensitive data", e);
        }
    }

    /**
     * Converts an encrypted string from the database to plain text.
     * 
     * @param encryptedText the encrypted string from the database
     * @return the decrypted plain text string, or null if input is null
     */
    @Override
    public String convertToEntityAttribute(String encryptedText) {
        if (encryptedText == null || encryptedText.trim().isEmpty()) {
            return null;
        }
        
        try {
            SecretKeySpec secretKeySpec = generateKey();
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Error decrypting sensitive data", e);
        }
    }

    /**
     * Generates a secret key from the configured secret key.
     * 
     * @return the SecretKeySpec for encryption/decryption
     * @throws Exception if key generation fails
     */
    private SecretKeySpec generateKey() throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(secretKey.getBytes(StandardCharsets.UTF_8));
        byte[] key = Arrays.copyOf(hash, 16); // AES requires 16, 24, or 32 bytes
        return new SecretKeySpec(key, ALGORITHM);
    }
}
