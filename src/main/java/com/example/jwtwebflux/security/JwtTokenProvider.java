package com.example.jwtwebflux.security;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import javax.crypto.SecretKey;
import java.util.*;
import java.util.function.Function;
@Slf4j
@Component
public class JwtTokenProvider {
    @Value("${app.jwt.secret}") private String jwtSecret;
    @Value("${app.jwt.expiration}") private long jwtExpiration;
    public String generateToken(String username, List<String> roles) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", roles);
        return buildToken(claims, username, jwtExpiration);
    }
    private String buildToken(Map<String, Object> extraClaims, String subject, long expiration) {
        return Jwts.builder().claims(extraClaims).subject(subject)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSigningKey()).compact();
    }
    public boolean isTokenValid(String token, String username) {
        try {
            return extractUsername(token).equals(username) && !isTokenExpired(token);
        } catch (JwtException | IllegalArgumentException e) {
            log.error("JWT token invalido: {}", e.getMessage());
            return false;
        }
    }
    public boolean validateToken(String token) {
        try {
            Jwts.parser().verifyWith(getSigningKey()).build().parseSignedClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            log.error("JWT invalido: {}", e.getMessage());
            return false;
        }
    }
    public String extractUsername(String token) { return extractClaim(token, Claims::getSubject); }
    public Date extractExpiration(String token) { return extractClaim(token, Claims::getExpiration); }
    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) { return (List<String>) extractAllClaims(token).get("roles"); }
    public long getExpirationInSeconds() { return jwtExpiration / 1000; }
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) { return claimsResolver.apply(extractAllClaims(token)); }
    private Claims extractAllClaims(String token) {
        return Jwts.parser().verifyWith(getSigningKey()).build().parseSignedClaims(token).getPayload();
    }
    private boolean isTokenExpired(String token) { return extractExpiration(token).before(new Date()); }
    private SecretKey getSigningKey() { return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret)); }
}