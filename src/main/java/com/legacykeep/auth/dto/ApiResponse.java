package com.legacykeep.auth.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Standard API Response DTO for Auth Service.
 * 
 * Provides consistent response structure across all endpoints.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ApiResponse<T> {
    
    /**
     * Response status (success/error)
     */
    private String status;
    
    /**
     * Response message
     */
    private String message;
    
    /**
     * Response data payload
     */
    private T data;
    
    /**
     * Timestamp of the response
     */
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
    private LocalDateTime timestamp;
    
    /**
     * Error details (if any)
     */
    private String error;
    
    /**
     * HTTP status code
     */
    private Integer statusCode;
    
    /**
     * Request path (for debugging)
     */
    private String path;
    
    /**
     * Create a successful response with data.
     * 
     * @param data Response data
     * @param message Success message
     * @return ApiResponse instance
     */
    public static <T> ApiResponse<T> success(T data, String message) {
        return ApiResponse.<T>builder()
                .status("success")
                .message(message)
                .data(data)
                .timestamp(LocalDateTime.now())
                .statusCode(200)
                .build();
    }
    
    /**
     * Create a successful response without data.
     * 
     * @param message Success message
     * @return ApiResponse instance
     */
    public static <T> ApiResponse<T> success(String message) {
        return ApiResponse.<T>builder()
                .status("success")
                .message(message)
                .timestamp(LocalDateTime.now())
                .statusCode(200)
                .build();
    }
    
    /**
     * Create an error response.
     * 
     * @param message Error message
     * @param error Error details
     * @param statusCode HTTP status code
     * @return ApiResponse instance
     */
    public static <T> ApiResponse<T> error(String message, String error, Integer statusCode) {
        return ApiResponse.<T>builder()
                .status("error")
                .message(message)
                .error(error)
                .timestamp(LocalDateTime.now())
                .statusCode(statusCode)
                .build();
    }
    
    /**
     * Create a validation error response.
     * 
     * @param message Error message
     * @return ApiResponse instance
     */
    public static <T> ApiResponse<T> validationError(String message) {
        return error(message, "Validation failed", 400);
    }
    
    /**
     * Create an unauthorized error response.
     * 
     * @param message Error message
     * @return ApiResponse instance
     */
    public static <T> ApiResponse<T> unauthorized(String message) {
        return error(message, "Unauthorized access", 401);
    }
    
    /**
     * Create a forbidden error response.
     * 
     * @param message Error message
     * @return ApiResponse instance
     */
    public static <T> ApiResponse<T> forbidden(String message) {
        return error(message, "Access forbidden", 403);
    }
    
    /**
     * Create a not found error response.
     * 
     * @param message Error message
     * @return ApiResponse instance
     */
    public static <T> ApiResponse<T> notFound(String message) {
        return error(message, "Resource not found", 404);
    }
    
    /**
     * Create an internal server error response.
     * 
     * @param message Error message
     * @return ApiResponse instance
     */
    public static <T> ApiResponse<T> internalError(String message) {
        return error(message, "Internal server error", 500);
    }
}

