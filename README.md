# jwt-webflux-auth

Spring WebFlux + Spring Security + JWT Authentication

## Usuarios de prueba
| Usuario | Contraseña | Roles |
|---------|-----------|-------|
| admin | admin123 | ROLE_ADMIN, ROLE_USER |
| user | user123 | ROLE_USER |

## Endpoints
| Método | Endpoint | Auth | Descripción |
|--------|----------|------|-------------|
| POST | /api/auth/login | No | Genera JWT |
| GET | /api/profile | Bearer | Perfil del usuario |
| GET | /api/admin/dashboard | Bearer (ADMIN) | Panel admin |

## Ejecutar
```bash
mvn spring-boot:run
```