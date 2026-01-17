package com.confiance.auth.controller;

import com.confiance.auth.dto.AuthResponse;
import com.confiance.auth.dto.ForgotPasswordRequest;
import com.confiance.auth.dto.RefreshTokenRequest;
import com.confiance.auth.dto.ResetPasswordRequest;
import com.confiance.auth.dto.TokenValidityResponse;
import com.confiance.auth.service.AuthService;
import com.confiance.auth.service.PasswordResetService;
import com.confiance.common.constants.ApiConstants;
import com.confiance.common.dto.ApiResponse;
import com.confiance.common.dto.LoginRequest;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(ApiConstants.AUTH_BASE)
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Authentication and Token Management APIs")
public class AuthController {

    private final AuthService authService;
    private final PasswordResetService passwordResetService;

    @PostMapping(ApiConstants.LOGIN)
    @Operation(summary = "Login", description = "Authenticate user and get access/refresh tokens")
    public ResponseEntity<ApiResponse<AuthResponse>> login(@Valid @RequestBody LoginRequest loginRequest) {
        AuthResponse authResponse = authService.login(loginRequest);
        return ResponseEntity.ok(ApiResponse.success("Login successful", authResponse));
    }

    @PostMapping(ApiConstants.REFRESH)
    @Operation(summary = "Refresh Token", description = "Get new access token using refresh token")
    public ResponseEntity<ApiResponse<AuthResponse>> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        AuthResponse authResponse = authService.refreshToken(request);
        return ResponseEntity.ok(ApiResponse.success("Token refreshed successfully", authResponse));
    }

    @PostMapping(ApiConstants.LOGOUT)
    @Operation(summary = "Logout", description = "Revoke user tokens")
    public ResponseEntity<ApiResponse<Void>> logout(@RequestHeader("X-Session-Id") String sessionId) {
        authService.logout(sessionId);
        return ResponseEntity.ok(ApiResponse.success("Logout successful", null));
    }

    @PostMapping("/forgot-password")
    @Operation(summary = "Forgot Password", description = "Request password reset email")
    public ResponseEntity<ApiResponse<Void>> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        passwordResetService.initiatePasswordReset(request);
        return ResponseEntity.ok(ApiResponse.success(
                "If the email exists, a password reset link will be sent", null));
    }

    @GetMapping("/verify-reset-token")
    @Operation(summary = "Verify Reset Token", description = "Check if password reset token is valid")
    public ResponseEntity<ApiResponse<TokenValidityResponse>> verifyResetToken(@RequestParam String token) {
        TokenValidityResponse response = passwordResetService.verifyResetToken(token);
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @PostMapping("/reset-password")
    @Operation(summary = "Reset Password", description = "Reset password using token")
    public ResponseEntity<ApiResponse<Void>> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        passwordResetService.resetPassword(request);
        return ResponseEntity.ok(ApiResponse.success("Password reset successful", null));
    }
}