package com.example.jwtwebflux.dto;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;
import java.util.List;
@Data @Builder @NoArgsConstructor @AllArgsConstructor
public class LoginResponse {
    @JsonProperty("access_token") private String accessToken;
    @JsonProperty("token_type") private String tokenType;
    @JsonProperty("expires_in") private long expiresIn;
    private String username;
    private List<String> roles;
}
