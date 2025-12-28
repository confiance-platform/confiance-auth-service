package com.confiance.auth.service;

import com.confiance.auth.dto.AuthResponse;
import com.confiance.auth.dto.RefreshTokenRequest;
import com.confiance.auth.entity.RefreshToken;
import com.confiance.auth.security.JwtTokenProvider;
import com.confiance.common.dto.ApiResponse;
import com.confiance.common.dto.LoginRequest;
import com.confiance.common.dto.UserInfo;
import com.confiance.common.enums.UserRole;
import com.confiance.common.exception.UnauthorizedException;
import com.confiance.common.security.JwtUser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final RestTemplate restTemplate;

    public AuthResponse login(LoginRequest loginRequest) {
        log.info("Login attempt for email: {}", loginRequest.getEmail());

        UserInfo userInfo = validateCredentialsWithUserService(loginRequest);

        String sessionId = UUID.randomUUID().toString();

        JwtUser jwtUser = JwtUser.builder()
                .userId(userInfo.getId())
                .email(userInfo.getEmail())
                .roles(userInfo.getRoles())
                .permissions(userInfo.getPermissions())
                .sessionId(sessionId)
                .build();

        String accessToken = jwtTokenProvider.generateAccessToken(jwtUser);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userInfo.getId(), sessionId);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken.getToken())
                .tokenType("Bearer")
                .expiresIn(jwtTokenProvider.getAccessExpirationMs() / 1000)
                .user(userInfo)
                .build();
    }

    public AuthResponse refreshToken(RefreshTokenRequest request) {
        log.info("Refresh token request");

        RefreshToken refreshToken = refreshTokenService.findByToken(request.getRefreshToken());
        refreshTokenService.verifyExpiration(refreshToken);

        UserInfo userInfo = getUserInfoFromUserService(refreshToken.getUserId());

        JwtUser jwtUser = JwtUser.builder()
                .userId(userInfo.getId())
                .email(userInfo.getEmail())
                .roles(userInfo.getRoles())
                .permissions(userInfo.getPermissions())
                .sessionId(refreshToken.getSessionId())
                .build();

        String newAccessToken = jwtTokenProvider.generateAccessToken(jwtUser);

        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(refreshToken.getToken())
                .tokenType("Bearer")
                .expiresIn(jwtTokenProvider.getAccessExpirationMs() / 1000)
                .user(userInfo)
                .build();
    }

    public void logout(String sessionId) {
        log.info("Logout request for session: {}", sessionId);
        refreshTokenService.revokeTokenBySessionId(sessionId);
    }

    private UserInfo validateCredentialsWithUserService(LoginRequest loginRequest) {
        try {
            String url = "http://user-service/api/v1/users/validate-credentials";
            HttpEntity<LoginRequest> request = new HttpEntity<>(loginRequest);

            ResponseEntity<ApiResponse<UserInfo>> responseEntity = restTemplate.exchange(
                url,
                HttpMethod.POST,
                request,
                new ParameterizedTypeReference<ApiResponse<UserInfo>>() {}
            );

            ApiResponse<UserInfo> response = responseEntity.getBody();
            if (response != null && response.isSuccess() && response.getData() != null) {
                return response.getData();
            }
        } catch (Exception e) {
            log.error("Error validating credentials: {}", e.getMessage());
        }

        throw new UnauthorizedException("Invalid email or password");
    }

    private UserInfo getUserInfoFromUserService(Long userId) {
        try {
            String url = "http://user-service/api/v1/users/" + userId + "/info";

            ResponseEntity<ApiResponse<UserInfo>> responseEntity = restTemplate.exchange(
                url,
                HttpMethod.GET,
                null,
                new ParameterizedTypeReference<ApiResponse<UserInfo>>() {}
            );

            ApiResponse<UserInfo> response = responseEntity.getBody();
            if (response != null && response.isSuccess() && response.getData() != null) {
                return response.getData();
            }
        } catch (Exception e) {
            log.error("Error fetching user info: {}", e.getMessage());
        }

        throw new UnauthorizedException("User not found");
    }
}