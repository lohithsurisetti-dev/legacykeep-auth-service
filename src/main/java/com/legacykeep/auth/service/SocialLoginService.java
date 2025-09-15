package com.legacykeep.auth.service;

import com.legacykeep.auth.dto.JwtTokenDto;
import com.legacykeep.auth.entity.User;

/**
 * Social Login Service Interface.
 * 
 * Provides methods for social login integration including:
 * - Google OAuth2 login
 * - Apple Sign-In
 * - Facebook login
 * - User account linking
 * 
 * @author LegacyKeep Team
 * @version 1.0.0
 */
public interface SocialLoginService {

    /**
     * Process Google OAuth2 login.
     * 
     * @param googleToken the Google ID token
     * @param deviceInfo client device information
     * @param ipAddress client IP address
     * @return JWT token response
     */
    JwtTokenDto processGoogleLogin(String googleToken, String deviceInfo, String ipAddress);

    /**
     * Process Apple Sign-In.
     * 
     * @param appleToken the Apple ID token
     * @param deviceInfo client device information
     * @param ipAddress client IP address
     * @return JWT token response
     */
    JwtTokenDto processAppleLogin(String appleToken, String deviceInfo, String ipAddress);

    /**
     * Process Facebook login.
     * 
     * @param facebookToken the Facebook access token
     * @param deviceInfo client device information
     * @param ipAddress client IP address
     * @return JWT token response
     */
    JwtTokenDto processFacebookLogin(String facebookToken, String deviceInfo, String ipAddress);

    /**
     * Link social account to existing user.
     * 
     * @param user the existing user
     * @param provider the social provider (google, apple, facebook)
     * @param socialId the social provider user ID
     * @param email the email from social provider
     */
    void linkSocialAccount(User user, String provider, String socialId, String email);

    /**
     * Unlink social account from user.
     * 
     * @param user the user
     * @param provider the social provider to unlink
     */
    void unlinkSocialAccount(User user, String provider);

    /**
     * Check if user has linked social account.
     * 
     * @param user the user
     * @param provider the social provider
     * @return true if linked, false otherwise
     */
    boolean hasLinkedSocialAccount(User user, String provider);
}
