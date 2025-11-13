package com.microservices.auth.security;

import com.microservices.auth.entity.AuthType;
import com.microservices.auth.entity.User;
import com.microservices.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final UserRepository userRepository;
    private final LdapTemplate ldapTemplate;
    
    @Value("${spring.ldap.user-dn-pattern:uid={0},ou=people}")
    private String userDnPattern;
    
    @Value("${auth.max-login-attempts:5}")
    private Integer maxLoginAttempts;
    
    @Value("${auth.lockout-duration-minutes:30}")
    private Integer lockoutDurationMinutes;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        log.debug("Attempting authentication for user: {}", username);

        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> {
                log.warn("User not found: {}", username);
                return new UsernameNotFoundException("Invalid username or password");
            });

        // Check if account is locked
        if (!user.getAccountNonLocked()) {
            if (user.getLockoutTime() != null) {
                LocalDateTime unlockTime = user.getLockoutTime()
                    .plusMinutes(lockoutDurationMinutes);
                
                if (LocalDateTime.now().isBefore(unlockTime)) {
                    log.warn("Account is locked for user: {}", username);
                    throw new LockedException(
                        "Account is locked due to multiple failed login attempts. " +
                        "Please try again after " + unlockTime);
                } else {
                    // Unlock account if lockout period has passed
                    user.setAccountNonLocked(true);
                    user.setFailedLoginAttempts(0);
                    user.setLockoutTime(null);
                    userRepository.save(user);
                    log.info("Account unlocked for user: {}", username);
                }
            }
        }

        // Check if user is enabled
        if (!user.getEnabled()) {
            log.warn("Account is disabled for user: {}", username);
            throw new BadCredentialsException("Account is disabled");
        }

        boolean authenticated = false;

        // Authenticate based on auth type
        if (user.getAuthType() == AuthType.LDAP) {
            log.debug("Authenticating user {} via LDAP", username);
            authenticated = authenticateWithLdap(username, password);
        } else {
            // DATABASE authentication is handled by DaoAuthenticationProvider
            log.debug("User {} uses DATABASE authentication, delegating to DaoAuthenticationProvider", username);
            return null; // Return null to allow other providers to handle
        }

        if (authenticated) {
            // Reset failed login attempts on successful authentication
            if (user.getFailedLoginAttempts() > 0) {
                user.setFailedLoginAttempts(0);
                user.setLockoutTime(null);
                userRepository.save(user);
            }
            
            user.setLastLoginAt(LocalDateTime.now());
            userRepository.save(user);

            List<GrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName().name()))
                .collect(Collectors.toList());

            log.info("User {} authenticated successfully", username);
            return new UsernamePasswordAuthenticationToken(user, password, authorities);
        } else {
            handleFailedLogin(user);
            throw new BadCredentialsException("Invalid username or password");
        }
    }

    private boolean authenticateWithLdap(String username, String password) {
        try {
            String userDn = userDnPattern.replace("{0}", username);
            
            LdapContextSource contextSource = new LdapContextSource();
            contextSource.setUrl(ldapTemplate.getContextSource().getReadOnlyContext().getEnvironment()
                .get("java.naming.provider.url").toString());
            contextSource.setUserDn(userDn);
            contextSource.setPassword(password);
            contextSource.afterPropertiesSet();
            
            // Try to get context - if successful, authentication is valid
            contextSource.getContext(userDn, password);
            
            log.debug("LDAP authentication successful for user: {}", username);
            return true;
        } catch (Exception e) {
            log.error("LDAP authentication failed for user: {}", username, e);
            return false;
        }
    }

    private void handleFailedLogin(User user) {
        int attempts = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(attempts);

        if (attempts >= maxLoginAttempts) {
            user.setAccountNonLocked(false);
            user.setLockoutTime(LocalDateTime.now());
            log.warn("Account locked for user: {} after {} failed attempts", 
                user.getUsername(), attempts);
        }

        userRepository.save(user);
        log.debug("Failed login attempt {} for user: {}", attempts, user.getUsername());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}