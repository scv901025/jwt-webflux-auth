package com.example.jwtwebflux.controller;
import com.example.jwtwebflux.dto.*;
import com.example.jwtwebflux.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;
@RestController @RequestMapping("/api/auth") @RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;
    @PostMapping("/login")
    public Mono<ResponseEntity<LoginResponse>> login(@RequestBody LoginRequest request) {
        return authService.login(request).map(ResponseEntity::ok).onErrorReturn(ResponseEntity.status(401).build());
    }
}