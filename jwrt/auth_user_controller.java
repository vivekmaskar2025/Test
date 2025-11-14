package com.microservices.auth.controller;

import com.microservices.auth.dto.UserDTO;
import com.microservices.auth.entity.User;
import com.microservices.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("/me")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<UserDTO> getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        
        log.info("Fetching profile for user: {}", username);
        UserDTO user = userService.getUserByUsername(username);
        return ResponseEntity.ok(user);
    }

    @GetMapping("/{username}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserDTO> getUserByUsername(@PathVariable String username) {
        log.info("Admin fetching profile for user: {}", username);
        UserDTO user = userService.getUserByUsername(username);
        return ResponseEntity.ok(user);
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<UserDTO>> getAllUsers() {
        log.info("Admin fetching all users");
        List<UserDTO> users = userService.getAllUsers();
        return ResponseEntity.ok(users);
    }

    @PutMapping("/me/password")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<MessageResponse> changePassword(
            @RequestBody ChangePasswordRequest request) {
        
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        
        log.info("Password change request for user: {}", username);
        userService.changePassword(username, request.getOldPassword(), request.getNewPassword());
        
        return ResponseEntity.ok(new MessageResponse("Password changed successfully"));
    }

    @PutMapping("/{username}/enable")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<MessageResponse> toggleUserStatus(
            @PathVariable String username,
            @RequestParam boolean enabled) {
        
        log.info("Admin toggling user status: {} to {}", username, enabled);
        userService.toggleUserStatus(username, enabled);
        
        return ResponseEntity.ok(
            new MessageResponse("User " + username + " " + (enabled ? "enabled" : "disabled")));
    }

    @PutMapping("/{username}/unlock")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<MessageResponse> unlockAccount(@PathVariable String username) {
        log.info("Admin unlocking account: {}", username);
        userService.unlockAccount(username);
        
        return ResponseEntity.ok(new MessageResponse("Account unlocked successfully"));
    }

    @DeleteMapping("/{username}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<MessageResponse> deleteUser(@PathVariable String username) {
        log.info("Admin deleting user: {}", username);
        userService.deleteUser(username);
        
        return ResponseEntity.ok(new MessageResponse("User deleted successfully"));
    }
}

@lombok.Data
@lombok.AllArgsConstructor
@lombok.NoArgsConstructor
class ChangePasswordRequest {
    private String oldPassword;
    private String newPassword;
}

class MessageResponse {
    private String message;
    
    public MessageResponse(String message) {
        this.message = message;
    }
    
    public String getMessage() {
        return message;
    }
    
    public void setMessage(String message) {
        this.message = message;
    }
}