package com.example.jwtwebflux.service;
import com.example.jwtwebflux.dto.*;
import com.example.jwtwebflux.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.*;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import java.util.List;
@Slf4j @Service @RequiredArgsConstructor
public class AuthService {
    private final ReactiveAuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    public Mono<LoginResponse> login(LoginRequest request) {
        return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()))
                .map(auth -> {
                    List<String> roles = auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
                    String token = jwtTokenProvider.generateToken(auth.getName(), roles);
                    return LoginResponse.builder().accessToken(token).tokenType("Bearer")
                            .expiresIn(jwtTokenProvider.getExpirationInSeconds()).username(auth.getName()).roles(roles).build();
                });
    }
}