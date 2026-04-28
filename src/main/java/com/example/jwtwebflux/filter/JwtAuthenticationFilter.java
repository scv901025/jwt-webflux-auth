package com.example.jwtwebflux.filter;
import com.example.jwtwebflux.security.CustomUserDetailsService;
import com.example.jwtwebflux.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.*;
import reactor.core.publisher.Mono;
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements WebFilter {
    private static final String BEARER_PREFIX = "Bearer ";
    private final JwtTokenProvider jwtTokenProvider;
    private final CustomUserDetailsService userDetailsService;
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String token = extractToken(exchange);
        if (token == null || !jwtTokenProvider.validateToken(token)) return chain.filter(exchange);
        String username = jwtTokenProvider.extractUsername(token);
        return userDetailsService.findByUsername(username)
                .filter(u -> jwtTokenProvider.isTokenValid(token, u.getUsername()))
                .map(u -> new UsernamePasswordAuthenticationToken(u, null, u.getAuthorities()))
                .flatMap(auth -> chain.filter(exchange).contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth)))
                .switchIfEmpty(chain.filter(exchange));
    }
    private String extractToken(ServerWebExchange exchange) {
        String h = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        return (StringUtils.hasText(h) && h.startsWith(BEARER_PREFIX)) ? h.substring(BEARER_PREFIX.length()) : null;
    }
}