package com.legacykeep.auth.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Standardized API Response for all Auth Service endpoints
 * 
 * This class provides a consistent response structure across all APIs
 * with proper error handling, metadata, and data encapsulation.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResponse<T> {

    // =============================================================================
    // Core Response Fields
    // =============================================================================

    /**
     * Indicates if the request was successful
     */
    private boolean success;

    /**
     * HTTP status code
     */
    private int statusCode;

    /**
     * Human-readable message
     */
    private String message;

    /**
     * Error code for programmatic handling
     */
    private String errorCode;

    /**
     * Detailed error message (only for errors)
     */
    private String errorDetails;

    /**
     * The actual response data
     */
    private T data;

    // =============================================================================
    // Metadata Fields
    // =============================================================================

    /**
     * Request timestamp
     */
    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
    private LocalDateTime timestamp;

    /**
     * Request ID for tracking
     */
    private String requestId;

    /**
     * API version
     */
    private String version;

    /**
     * Processing time in milliseconds
     */
    private Long processingTimeMs;

    // =============================================================================
    // Pagination Fields (for list responses)
    // =============================================================================

    /**
     * Pagination information
     */
    private PaginationInfo pagination;

    // =============================================================================
    // Static Factory Methods for Success Responses
    // =============================================================================

    /**
     * Create a successful response with data
     */
    public static <T> ApiResponse<T> success(T data) {
        return ApiResponse.<T>builder()
                .success(true)
                .statusCode(200)
                .message("Success")
                .data(data)
                .timestamp(LocalDateTime.now())
                .version("1.0")
                .build();
    }

    /**
     * Create a successful response with custom message
     */
    public static <T> ApiResponse<T> success(T data, String message) {
        return ApiResponse.<T>builder()
                .success(true)
                .statusCode(200)
                .message(message)
                .data(data)
                .timestamp(LocalDateTime.now())
                .version("1.0")
                .build();
    }

    /**
     * Create a successful response with custom status code
     */
    public static <T> ApiResponse<T> success(T data, String message, int statusCode) {
        return ApiResponse.<T>builder()
                .success(true)
                .statusCode(statusCode)
                .message(message)
                .data(data)
                .timestamp(LocalDateTime.now())
                .version("1.0")
                .build();
    }

    /**
     * Create a successful response without data
     */
    public static <T> ApiResponse<T> success(String message) {
        return ApiResponse.<T>builder()
                .success(true)
                .statusCode(200)
                .message(message)
                .timestamp(LocalDateTime.now())
                .version("1.0")
                .build();
    }

    /**
     * Create a successful response with pagination
     */
    public static <T> ApiResponse<T> success(T data, String message, PaginationInfo pagination) {
        return ApiResponse.<T>builder()
                .success(true)
                .statusCode(200)
                .message(message)
                .data(data)
                .pagination(pagination)
                .timestamp(LocalDateTime.now())
                .version("1.0")
                .build();
    }

    // =============================================================================
    // Static Factory Methods for Error Responses
    // =============================================================================

    /**
     * Create an error response
     */
    public static <T> ApiResponse<T> error(String message, String errorCode) {
        return ApiResponse.<T>builder()
                .success(false)
                .statusCode(400)
                .message(message)
                .errorCode(errorCode)
                .timestamp(LocalDateTime.now())
                .version("1.0")
                .build();
    }

    /**
     * Create an error response with details
     */
    public static <T> ApiResponse<T> error(String message, String errorCode, String errorDetails) {
        return ApiResponse.<T>builder()
                .success(false)
                .statusCode(400)
                .message(message)
                .errorCode(errorCode)
                .errorDetails(errorDetails)
                .timestamp(LocalDateTime.now())
                .version("1.0")
                .build();
    }

    /**
     * Create an error response with custom status code
     */
    public static <T> ApiResponse<T> error(String message, String errorCode, int statusCode) {
        return ApiResponse.<T>builder()
                .success(false)
                .statusCode(statusCode)
                .message(message)
                .errorCode(errorCode)
                .timestamp(LocalDateTime.now())
                .version("1.0")
                .build();
    }

    /**
     * Create an error response with custom status code and details
     */
    public static <T> ApiResponse<T> error(String message, String errorCode, String errorDetails, int statusCode) {
        return ApiResponse.<T>builder()
                .success(false)
                .statusCode(statusCode)
                .message(message)
                .errorCode(errorCode)
                .errorDetails(errorDetails)
                .timestamp(LocalDateTime.now())
                .version("1.0")
                .build();
    }

    // =============================================================================
    // Utility Methods
    // =============================================================================

    /**
     * Set request ID for tracking
     */
    public ApiResponse<T> withRequestId(String requestId) {
        this.requestId = requestId;
        return this;
    }

    /**
     * Set processing time
     */
    public ApiResponse<T> withProcessingTime(Long processingTimeMs) {
        this.processingTimeMs = processingTimeMs;
        return this;
    }

    /**
     * Set pagination info
     */
    public ApiResponse<T> withPagination(PaginationInfo pagination) {
        this.pagination = pagination;
        return this;
    }

    // =============================================================================
    // Inner Classes
    // =============================================================================

    /**
     * Pagination information for list responses
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class PaginationInfo {
        private int page;
        private int size;
        private long totalElements;
        private int totalPages;
        private boolean hasNext;
        private boolean hasPrevious;
        private String nextPageUrl;
        private String previousPageUrl;
    }
}
