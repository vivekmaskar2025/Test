package com.microservices.auth.service;

import com.microservices.auth.dto.*;
import com.microservices.auth.entity.*;
import com.microservices.auth.exception.*;
import com.microservices.auth.repository.*;
import com.microservices.auth.util.JwtUtil;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final TokenBlacklistRepository tokenBlacklistRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;
    private final CustomUserDetailsService userDetailsService;

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        log.info("Registering new user: {}", request.getUsername());

        // Validate request
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new UserAlreadyExistsException("Username already exists: " + request.getUsername());
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new UserAlreadyExistsException("Email already exists: " + request.getEmail());
        }

        // Create user
        Set<Role> roles = new HashSet<>();
        Role userRole = roleRepository.findByName(RoleName.ROLE_USER)
            .orElseThrow(() -> new ResourceNotFoundException("Role not found: ROLE_USER"));
        roles.add(userRole);

        User user = User.builder()
            .username(request.getUsername())
            .email(request.getEmail())
            .password(passwordEncoder.encode(request.getPassword()))
            .authType(AuthType.DATABASE)
            .roles(roles)
            .enabled(true)
            .accountNonLocked(true)
            .failedLoginAttempts(0)
            .build();

        user = userRepository.save(user);
        log.info("User registered successfully: {}", user.getUsername());

        // Generate tokens
        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
        String accessToken = jwtUtil.generateToken(userDetails);
        String refreshToken = jwtUtil.generateRefreshToken(userDetails);

        // Save refresh token
        saveRefreshToken(user, refreshToken);

        return AuthResponse.builder()
            .accessToken(accessToken)
            .refreshToken(refreshToken)
            .tokenType("Bearer")
            .expiresIn(jwtUtil.getExpirationTimeInMillis())
            .username(user.getUsername())
            .roles(user.getRoles().stream()
                .map(role -> role.getName().name())
                .collect(Collectors.toList()))
            .build();
    }

    @Transactional
    public AuthResponse login(LoginRequest request) {
        log.info("Login attempt for user: {}", request.getUsername());

        try {
            // Authenticate user
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    request.getUsername(),
                    request.getPassword()
                )
            );

            User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

            // Update last login time
            user.setLastLoginAt(LocalDateTime.now());
            userRepository.save(user);

            // Generate tokens
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            String accessToken = jwtUtil.generateToken(userDetails);
            String refreshToken = jwtUtil.generateRefreshToken(userDetails);

            // Revoke old refresh tokens and save new one
            refreshTokenRepository.deleteByUserId(user.getId());
            saveRefreshToken(user, refreshToken);

            log.info("User logged in successfully: {}", user.getUsername());

            return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtUtil.getExpirationTimeInMillis())
                .username(user.getUsername())
                .roles(user.getRoles().stream()
                    .map(role -> role.getName().name())
                    .collect(Collectors.toList()))
                .build();

        } catch (BadCredentialsException e) {
            log.warn("Invalid credentials for user: {}", request.getUsername());
            throw new InvalidCredentialsException("Invalid username or password");
        }
    }

    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest request) {
        log.debug("Refreshing token");

        String refreshToken = request.getRefreshToken();

        // Validate refresh token
        if (!jwtUtil.validateToken(refreshToken)) {
            throw new InvalidTokenException("Invalid refresh token");
        }

        // Check if token is in database and not revoked
        RefreshToken storedToken = refreshTokenRepository.findByToken(refreshToken)
            .orElseThrow(() -> new InvalidTokenException("Refresh token not found"));

        if (storedToken.getRevoked()) {
            throw new InvalidTokenException("Refresh token has been revoked");
        }

        if (storedToken.getExpiryDate().isBefore(LocalDateTime.now())) {
            throw new InvalidTokenException("Refresh token has expired");
        }

        // Generate new access token
        String username = jwtUtil.extractUsername(refreshToken);
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        String newAccessToken = jwtUtil.generateToken(userDetails);

        log.info("Token refreshed successfully for user: {}", username);

        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return AuthResponse.builder()
            .accessToken(newAccessToken)
            .refreshToken(refreshToken)
            .tokenType("Bearer")
            .expiresIn(jwtUtil.getExpirationTimeInMillis())
            .username(username)
            .roles(user.getRoles().stream()
                .map(role -> role.getName().name())
                .collect(Collectors.toList()))
            .build();
    }

    @Transactional
    public void logout(LogoutRequest request) {
        log.info("Logout requested");

        String token = request.getToken();

        // Add token to blacklist
        if (!tokenBlacklistRepository.existsByToken(token)) {
            TokenBlacklist blacklistedToken = TokenBlacklist.builder()
                .token(token)
                .expiryDate(jwtUtil.extractExpiration(token).toInstant()
                    .atZone(java.time.ZoneId.systemDefault()).toLocalDateTime())
                .build();

            tokenBlacklistRepository.save(blacklistedToken);
        }

        // Revoke refresh token if provided
        if (request.getRefreshToken() != null) {
            refreshTokenRepository.revokeToken(request.getRefreshToken());
        }

        log.info("User logged out successfully");
    }

    @Transactional(readOnly = true)
    public TokenValidationResponse validateToken(TokenValidationRequest request) {
        log.debug("Validating token");

        String token = request.getToken();

        try {
            // Check if token is blacklisted
            if (tokenBlacklistRepository.existsByToken(token)) {
                return TokenValidationResponse.builder()
                    .valid(false)
                    .message("Token has been revoked")
                    .build();
            }

            // Validate token
            if (!jwtUtil.validateToken(token)) {
                return TokenValidationResponse.builder()
                    .valid(false)
                    .message("Invalid token")
                    .build();
            }

            // Extract user information
            String username = jwtUtil.extractUsername(token);
            User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

            List<String> roles = user.getRoles().stream()
                .map(role -> role.getName().name())
                .collect(Collectors.toList());

            return TokenValidationResponse.builder()
                .valid(true)
                .userId(user.getId().toString())
                .username(user.getUsername())
                .roles(roles)
                .message("Token is valid")
                .build();

        } catch (JwtException e) {
            log.error("JWT validation error", e);
            return TokenValidationResponse.builder()
                .valid(false)
                .message("Token validation failed: " + e.getMessage())
                .build();
        }
    }

    private void saveRefreshToken(User user, String token) {
        LocalDateTime expiryDate = LocalDateTime.now()
            .plusSeconds(jwtUtil.getRefreshExpirationTimeInMillis() / 1000);

        RefreshToken refreshToken = RefreshToken.builder()
            .token(token)
            .user(user)
            .expiryDate(expiryDate)
            .revoked(false)
            .build();

        refreshTokenRepository.save(refreshToken);
    }

    @Scheduled(cron = "0 0 * * * *") // Run every hour
    @Transactional
    public void cleanupExpiredTokens() {
        log.info("Starting cleanup of expired tokens");
        
        LocalDateTime now = LocalDateTime.now();
        refreshTokenRepository.deleteExpiredTokens(now);
        tokenBlacklistRepository.deleteExpiredTokens(now);
        
        log.info("Expired tokens cleanup completed");
    }
}