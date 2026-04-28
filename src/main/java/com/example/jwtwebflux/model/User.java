package com.example.jwtwebflux.model;
import lombok.*;
import java.util.List;
@Data @Builder @NoArgsConstructor @AllArgsConstructor
public class User {
    private String id;
    private String username;
    private String password;
    private String email;
    private List<String> roles;
    private boolean active;
}
