package com.legacykeep.auth.dto;

import lombok.Builder;
import lombok.Data;

/**
 * Encryption Statistics DTO for reporting encryption status.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Data
@Builder
public class EncryptionStatistics {

    /**
     * Total number of records processed.
     */
    private long totalRecords;

    /**
     * Number of records successfully encrypted.
     */
    private long encryptedRecords;

    /**
     * Number of records that were already encrypted.
     */
    private long alreadyEncryptedRecords;

    /**
     * Number of records that failed encryption.
     */
    private long failedRecords;

    /**
     * Encryption success rate as a percentage.
     */
    private double successRate;

    /**
     * Time taken for encryption process in milliseconds.
     */
    private long processingTimeMs;

    /**
     * Status of encryption process.
     */
    private String status;

    /**
     * Error message if encryption failed.
     */
    private String errorMessage;
}
