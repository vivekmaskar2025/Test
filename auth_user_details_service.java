package com.microservices.auth.service;

import com.microservices.auth.entity.User;
import com.microservices.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.debug("Loading user by username: {}", username);
        
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> {
                log.warn("User not found with username: {}", username);
                return new UsernameNotFoundException("User not found: " + username);
            });

        return buildUserDetails(user);
    }

    private UserDetails buildUserDetails(User user) {
        Collection<GrantedAuthority> authorities = user.getRoles().stream()
            .map(role -> new SimpleGrantedAuthority(role.getName().name()))
            .collect(Collectors.toList());

        boolean accountNonLocked = user.getAccountNonLocked();
        if (!accountNonLocked && user.getLockoutTime() != null) {
            // Check if lockout period has expired
            LocalDateTime unlockTime = user.getLockoutTime().plusMinutes(30);
            if (LocalDateTime.now().isAfter(unlockTime)) {
                accountNonLocked = true;
            }
        }

        return org.springframework.security.core.userdetails.User.builder()
            .username(user.getUsername())
            .password(user.getPassword())
            .authorities(authorities)
            .accountExpired(false)
            .accountLocked(!accountNonLocked)
            .credentialsExpired(false)
            .disabled(!user.getEnabled())
            .build();
    }
}