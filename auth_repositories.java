package com.microservices.auth.repository;

import com.microservices.auth.entity.*;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    Optional<User> findByUsername(String username);
    
    Optional<User> findByEmail(String email);
    
    boolean existsByUsername(String username);
    
    boolean existsByEmail(String email);
    
    @Modifying
    @Query("UPDATE User u SET u.failedLoginAttempts = :attempts, u.lockoutTime = :lockoutTime WHERE u.id = :userId")
    void updateFailedLoginAttempts(@Param("userId") Long userId, 
                                   @Param("attempts") Integer attempts, 
                                   @Param("lockoutTime") LocalDateTime lockoutTime);
    
    @Modifying
    @Query("UPDATE User u SET u.lastLoginAt = :loginTime WHERE u.id = :userId")
    void updateLastLoginTime(@Param("userId") Long userId, @Param("loginTime") LocalDateTime loginTime);
}

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    
    Optional<Role> findByName(RoleName name);
    
    boolean existsByName(RoleName name);
}

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    
    Optional<RefreshToken> findByToken(String token);
    
    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.user.id = :userId")
    void deleteByUserId(@Param("userId") Long userId);
    
    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiryDate < :now")
    void deleteExpiredTokens(@Param("now") LocalDateTime now);
    
    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.revoked = true WHERE rt.token = :token")
    void revokeToken(@Param("token") String token);
}

@Repository
public interface TokenBlacklistRepository extends JpaRepository<TokenBlacklist, Long> {
    
    boolean existsByToken(String token);
    
    @Modifying
    @Query("DELETE FROM TokenBlacklist tb WHERE tb.expiryDate < :now")
    void deleteExpiredTokens(@Param("now") LocalDateTime now);
}