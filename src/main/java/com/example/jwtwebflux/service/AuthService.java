package com.example.jwtwebflux.service;

import com.example.jwtwebflux.dto.LoginRequest;
import com.example.jwtwebflux.dto.LoginResponse;
import com.example.jwtwebflux.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final ReactiveAuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;

    public Mono<LoginResponse> login(LoginRequest request) {
        log.info("Intento de login para usuario: {}", request.getUsername());
        return authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                ))
                .map(this::buildLoginResponse)
                .doOnSuccess(r -> log.info("Login exitoso para: {}", r.getUsername()))
                .doOnError(e -> log.error("Login fallido para {}: {}", request.getUsername(), e.getMessage()));
    }

    private LoginResponse buildLoginResponse(Authentication authentication) {
        List<String> roles = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        String token = jwtTokenProvider.generateToken(authentication.getName(), roles);

        return LoginResponse.builder()
                .accessToken(token)
                .tokenType("Bearer")
                .expiresIn(jwtTokenProvider.getExpirationInSeconds())
                .username(authentication.getName())
                .roles(roles)
                .build();
    }
}