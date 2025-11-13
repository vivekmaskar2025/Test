package com.microservices.auth.config;

import com.microservices.auth.entity.Role;
import com.microservices.auth.entity.RoleName;
import com.microservices.auth.entity.User;
import com.microservices.auth.entity.AuthType;
import com.microservices.auth.repository.RoleRepository;
import com.microservices.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

@Slf4j
@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        log.info("Initializing default data...");
        
        // Initialize roles
        initializeRoles();
        
        // Initialize default admin user
        initializeDefaultAdmin();
        
        log.info("Data initialization completed");
    }

    private void initializeRoles() {
        for (RoleName roleName : RoleName.values()) {
            if (!roleRepository.existsByName(roleName)) {
                Role role = Role.builder()
                    .name(roleName)
                    .description(getDescriptionForRole(roleName))
                    .build();
                roleRepository.save(role);
                log.info("Created role: {}", roleName);
            }
        }
    }

    private void initializeDefaultAdmin() {
        String adminUsername = "admin";
        
        if (!userRepository.existsByUsername(adminUsername)) {
            Set<Role> roles = new HashSet<>();
            
            // Add all roles to admin
            roleRepository.findByName(RoleName.ROLE_ADMIN)
                .ifPresent(roles::add);
            roleRepository.findByName(RoleName.ROLE_USER)
                .ifPresent(roles::add);

            User admin = User.builder()
                .username(adminUsername)
                .email("admin@example.com")
                .password(passwordEncoder.encode("Admin@123"))
                .authType(AuthType.DATABASE)
                .roles(roles)
                .enabled(true)
                .accountNonLocked(true)
                .failedLoginAttempts(0)
                .build();

            userRepository.save(admin);
            log.info("Created default admin user - Username: admin, Password: Admin@123");
            log.warn("IMPORTANT: Please change the default admin password immediately!");
        }
    }

    private String getDescriptionForRole(RoleName roleName) {
        return switch (roleName) {
            case ROLE_USER -> "Standard user role with basic permissions";
            case ROLE_ADMIN -> "Administrator role with full system access";
            case ROLE_MODERATOR -> "Moderator role with elevated permissions";
        };
    }
}