package com.confiance.auth.service;

import com.confiance.auth.dto.ForgotPasswordRequest;
import com.confiance.auth.dto.ResetPasswordRequest;
import com.confiance.auth.dto.TokenValidityResponse;
import com.confiance.auth.entity.PasswordResetToken;
import com.confiance.auth.repository.PasswordResetTokenRepository;
import com.confiance.common.dto.ApiResponse;
import com.confiance.common.dto.UserInfo;
import com.confiance.common.exception.BadRequestException;
import com.confiance.common.exception.ResourceNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class PasswordResetService {

    private final PasswordResetTokenRepository tokenRepository;
    private final RestTemplate restTemplate;

    @Value("${password.reset.token.expiry-hours:24}")
    private int tokenExpiryHours;

    @Value("${app.frontend-url:http://localhost:3000}")
    private String frontendUrl;

    @Transactional
    public void initiatePasswordReset(ForgotPasswordRequest request) {
        String email = request.getEmail().toLowerCase().trim();
        log.info("Initiating password reset for email: {}", email);

        // Check if user exists
        UserInfo userInfo = findUserByEmail(email);
        if (userInfo == null) {
            // Don't reveal that user doesn't exist for security
            log.warn("Password reset requested for non-existent email: {}", email);
            return;
        }

        // Invalidate any existing tokens for this user
        tokenRepository.invalidateAllUserTokens(userInfo.getId());

        // Create new token
        String token = UUID.randomUUID().toString();
        PasswordResetToken resetToken = PasswordResetToken.builder()
                .token(token)
                .userId(userInfo.getId())
                .email(email)
                .expiryDate(LocalDateTime.now().plusHours(tokenExpiryHours))
                .used(false)
                .build();

        tokenRepository.save(resetToken);
        log.info("Password reset token created for user: {}", userInfo.getId());

        // Send email via notification service
        sendPasswordResetEmail(email, token, userInfo.getFirstName());
    }

    public TokenValidityResponse verifyResetToken(String token) {
        log.info("Verifying password reset token");

        PasswordResetToken resetToken = tokenRepository.findByTokenAndUsedFalse(token)
                .orElse(null);

        if (resetToken == null) {
            return TokenValidityResponse.builder()
                    .valid(false)
                    .message("Invalid or expired reset token")
                    .build();
        }

        if (resetToken.isExpired()) {
            return TokenValidityResponse.builder()
                    .valid(false)
                    .message("Reset token has expired")
                    .build();
        }

        return TokenValidityResponse.builder()
                .valid(true)
                .email(maskEmail(resetToken.getEmail()))
                .message("Token is valid")
                .build();
    }

    @Transactional
    public void resetPassword(ResetPasswordRequest request) {
        log.info("Processing password reset");

        // Validate passwords match
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new BadRequestException("Passwords do not match");
        }

        // Find and validate token
        PasswordResetToken resetToken = tokenRepository.findByTokenAndUsedFalse(request.getToken())
                .orElseThrow(() -> new BadRequestException("Invalid or expired reset token"));

        if (resetToken.isExpired()) {
            throw new BadRequestException("Reset token has expired");
        }

        // Update password in user service
        updateUserPassword(resetToken.getUserId(), request.getNewPassword());

        // Mark token as used
        resetToken.setUsed(true);
        tokenRepository.save(resetToken);

        // Invalidate all refresh tokens for security
        invalidateUserSessions(resetToken.getUserId());

        log.info("Password reset successful for user: {}", resetToken.getUserId());
    }

    private UserInfo findUserByEmail(String email) {
        try {
            String userByEmailUrl = "http://user-service/api/v1/users/by-email?email=" + email;
            ResponseEntity<ApiResponse<UserInfo>> userResponse = restTemplate.exchange(
                    userByEmailUrl,
                    HttpMethod.GET,
                    null,
                    new ParameterizedTypeReference<ApiResponse<UserInfo>>() {}
            );
            if (userResponse.getBody() != null && userResponse.getBody().isSuccess()) {
                return userResponse.getBody().getData();
            }
        } catch (Exception e) {
            log.debug("User not found by email: {}", email);
        }
        return null;
    }

    private void updateUserPassword(Long userId, String newPassword) {
        try {
            String url = "http://user-service/api/v1/users/" + userId + "/password";
            Map<String, String> body = Map.of("password", newPassword);
            HttpEntity<Map<String, String>> request = new HttpEntity<>(body);

            restTemplate.exchange(
                    url,
                    HttpMethod.PUT,
                    request,
                    new ParameterizedTypeReference<ApiResponse<Void>>() {}
            );
        } catch (Exception e) {
            log.error("Error updating password for user {}: {}", userId, e.getMessage());
            throw new BadRequestException("Failed to update password");
        }
    }

    private void invalidateUserSessions(Long userId) {
        try {
            // This would invalidate all refresh tokens for the user
            // Implementation depends on your RefreshTokenService
            log.info("Invalidating all sessions for user: {}", userId);
        } catch (Exception e) {
            log.warn("Could not invalidate sessions for user {}: {}", userId, e.getMessage());
        }
    }

    private void sendPasswordResetEmail(String email, String token, String firstName) {
        try {
            String url = "http://notification-service/api/v1/notifications/send-email";
            String resetLink = frontendUrl + "/reset-password?token=" + token;

            Map<String, Object> emailRequest = Map.of(
                    "to", email,
                    "subject", "Password Reset Request - Confiance",
                    "templateName", "password-reset",
                    "templateVariables", Map.of(
                            "firstName", firstName != null ? firstName : "User",
                            "resetToken", token,
                            "resetLink", resetLink,
                            "expiryHours", String.valueOf(tokenExpiryHours)
                    ),
                    "isHtml", true
            );
            HttpEntity<Map<String, Object>> request = new HttpEntity<>(emailRequest);

            restTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    request,
                    new ParameterizedTypeReference<ApiResponse<Object>>() {}
            );
            log.info("Password reset email sent to: {}", email);
        } catch (Exception e) {
            log.error("Failed to send password reset email: {}", e.getMessage(), e);
            // Don't throw - we still want the token to be created even if email fails
        }
    }

    private String maskEmail(String email) {
        if (email == null || !email.contains("@")) {
            return "***";
        }
        String[] parts = email.split("@");
        String localPart = parts[0];
        String domain = parts[1];

        if (localPart.length() <= 2) {
            return localPart.charAt(0) + "***@" + domain;
        }
        return localPart.substring(0, 2) + "***@" + domain;
    }
}
