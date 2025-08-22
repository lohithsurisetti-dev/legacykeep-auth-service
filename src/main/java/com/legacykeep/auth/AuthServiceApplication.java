package com.legacykeep.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;

/**
 * LegacyKeep Auth Service Application
 * 
 * This is the main entry point for the Authentication and Authorization microservice.
 * It handles user registration, login, session management, and security features.
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
@SpringBootApplication
@EnableFeignClients
public class AuthServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
    }
}

