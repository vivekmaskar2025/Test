package com.microservices.auth.service;

import com.microservices.auth.dto.UserDTO;
import com.microservices.auth.entity.User;
import com.microservices.auth.exception.InvalidCredentialsException;
import com.microservices.auth.exception.ResourceNotFoundException;
import com.microservices.auth.repository.RefreshTokenRepository;
import com.microservices.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional(readOnly = true)
    public UserDTO getUserByUsername(String username) {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new ResourceNotFoundException("User not found: " + username));
        
        return convertToDTO(user);
    }

    @Transactional(readOnly = true)
    public List<UserDTO> getAllUsers() {
        return userRepository.findAll().stream()
            .map(this::convertToDTO)
            .collect(Collectors.toList());
    }

    @Transactional
    public void changePassword(String username, String oldPassword, String newPassword) {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new ResourceNotFoundException("User not found: " + username));

        // Verify old password
        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
            throw new InvalidCredentialsException("Current password is incorrect");
        }

        // Validate new password
        if (newPassword == null || newPassword.length() < 8) {
            throw new IllegalArgumentException("New password must be at least 8 characters");
        }

        // Update password
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        // Revoke all refresh tokens to force re-login
        refreshTokenRepository.deleteByUserId(user.getId());

        log.info("Password changed successfully for user: {}", username);
    }

    @Transactional
    public void toggleUserStatus(String username, boolean enabled) {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new ResourceNotFoundException("User not found: " + username));

        user.setEnabled(enabled);
        userRepository.save(user);

        // If disabling, revoke all tokens
        if (!enabled) {
            refreshTokenRepository.deleteByUserId(user.getId());
        }

        log.info("User {} status changed to: {}", username, enabled ? "enabled" : "disabled");
    }

    @Transactional
    public void unlockAccount(String username) {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new ResourceNotFoundException("User not found: " + username));

        user.setAccountNonLocked(true);
        user.setFailedLoginAttempts(0);
        user.setLockoutTime(null);
        userRepository.save(user);

        log.info("Account unlocked for user: {}", username);
    }

    @Transactional
    public void deleteUser(String username) {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new ResourceNotFoundException("User not found: " + username));

        // Delete all refresh tokens first
        refreshTokenRepository.deleteByUserId(user.getId());

        // Delete user
        userRepository.delete(user);

        log.info("User deleted: {}", username);
    }

    private UserDTO convertToDTO(User user) {
        return UserDTO.builder()
            .id(user.getId())
            .username(user.getUsername())
            .email(user.getEmail())
            .enabled(user.getEnabled())
            .accountNonLocked(user.getAccountNonLocked())
            .authType(user.getAuthType().name())
            .roles(user.getRoles().stream()
                .map(role -> role.getName().name())
                .collect(Collectors.toList()))
            .createdAt(user.getCreatedAt())
            .lastLoginAt(user.getLastLoginAt())
            .build();
    }
}