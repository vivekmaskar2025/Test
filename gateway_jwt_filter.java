package com.microservices.gateway.filter;

import com.microservices.gateway.dto.TokenValidationRequest;
import com.microservices.gateway.dto.TokenValidationResponse;
import com.microservices.gateway.exception.UnauthorizedException;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.List;

@Slf4j
@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    private final WebClient.Builder webClientBuilder;
    
    @Value("${auth-service.url}")
    private String authServiceUrl;

    public JwtAuthenticationFilter(WebClient.Builder webClientBuilder) {
        super(Config.class);
        this.webClientBuilder = webClientBuilder;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            log.debug("JWT Authentication Filter executing for path: {}", 
                exchange.getRequest().getPath());

            // Extract Authorization header
            List<String> authHeaders = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION);
            
            if (authHeaders == null || authHeaders.isEmpty()) {
                log.warn("Missing Authorization header");
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }

            String authHeader = authHeaders.get(0);
            
            if (!authHeader.startsWith("Bearer ")) {
                log.warn("Invalid Authorization header format");
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }

            String token = authHeader.substring(7);

            // Validate token with Auth Service
            return validateToken(token)
                .flatMap(validationResponse -> {
                    if (!validationResponse.isValid()) {
                        log.warn("Token validation failed: {}", validationResponse.getMessage());
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    }

                    log.debug("Token validated successfully for user: {}", 
                        validationResponse.getUsername());

                    // Add user information to request headers
                    var modifiedRequest = exchange.getRequest().mutate()
                        .header("X-User-Id", validationResponse.getUserId())
                        .header("X-Username", validationResponse.getUsername())
                        .header("X-User-Roles", String.join(",", validationResponse.getRoles()))
                        .build();

                    return chain.filter(exchange.mutate().request(modifiedRequest).build());
                })
                .onErrorResume(error -> {
                    log.error("Error during token validation", error);
                    exchange.getResponse().setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
                    return exchange.getResponse().setComplete();
                });
        };
    }

    @CircuitBreaker(name = "authService", fallbackMethod = "fallbackValidateToken")
    private Mono<TokenValidationResponse> validateToken(String token) {
        log.debug("Validating token with Auth Service");
        
        TokenValidationRequest request = TokenValidationRequest.builder()
            .token(token)
            .build();

        return webClientBuilder.build()
            .post()
            .uri(authServiceUrl + "/api/auth/validate")
            .bodyValue(request)
            .retrieve()
            .onStatus(HttpStatusCode::isError, response -> {
                log.error("Auth service returned error status: {}", response.statusCode());
                return response.bodyToMono(String.class)
                    .flatMap(body -> Mono.error(
                        new UnauthorizedException("Token validation failed: " + body)));
            })
            .bodyToMono(TokenValidationResponse.class)
            .doOnSuccess(resp -> log.debug("Token validation successful"))
            .doOnError(error -> log.error("Token validation error", error));
    }

    private Mono<TokenValidationResponse> fallbackValidateToken(String token, Throwable throwable) {
        log.error("Circuit breaker fallback triggered for token validation", throwable);
        return Mono.error(new UnauthorizedException(
            "Authentication service temporarily unavailable. Please try again later."));
    }

    public static class Config {
        // Configuration properties if needed
    }
}