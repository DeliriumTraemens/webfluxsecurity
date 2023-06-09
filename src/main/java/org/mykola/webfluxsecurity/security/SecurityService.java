package org.mykola.webfluxsecurity.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.mykola.webfluxsecurity.entity.UserEntity;
import org.mykola.webfluxsecurity.exception.AuthException;
import org.mykola.webfluxsecurity.repository.UserRepository;
import org.mykola.webfluxsecurity.service.UserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.*;

@Component
@RequiredArgsConstructor
public class SecurityService {
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    @Value("${jwt.secret}")
    private String secret;
    @Value("${jwt.expiration}")
    private Integer expirationInSeconds;
    @Value("${jwt.issuer}")
    private String issuer;

    // Вытаскиваем из юзера роль и юзернейм и ложим их в claims
//И передаем дальше (claims, и в качестве сабжекта user.Id стрингой)
    private TokenDetails generateToken(UserEntity user) {
        Map<String, Object> claims = new HashMap<>() {{
            put("role", user.getRole());
            put("username", user.getUsername());
        }};
        return generateToken(claims, user.getId().toString());
    }
//    Принимаем клеймс и сабж -- Id
//    И НЕ обрабатывая их
//    Создаем Date expirationDate
//    Передаем дальше созданный expirationDate, claims, subj
    private TokenDetails generateToken(Map<String, Object> claims, String subject) {
        Long expirationTimeInMillis = expirationInSeconds * 1000L;
        Date expirationDate = new Date(new Date().getTime() + expirationTimeInMillis);

        return generateToken(expirationDate, claims, subject);
    }
// Наконец при помощи переданных аргументов
//    Генерим ТОКЕН, помещая в него
//    Claims, Issuer, Subj(userId), дату выпуска, рандомный Айдишник самого токена, дату протухания, Подпись
    private TokenDetails generateToken(Date expirationDate, Map<String, Object> claims, String subject) {

        Date createdDate = new Date();
        String token = Jwts.builder()
                .setClaims(claims)
                .setIssuer(issuer)
                .setSubject(subject)
                .setIssuedAt(createdDate)
                .setId(UUID.randomUUID().toString())
                .setExpiration(expirationDate)
                .signWith(SignatureAlgorithm.HS256, Base64.getEncoder().encodeToString(secret.getBytes()))
                .compact();

//    И наконец возвращаем TokenDetails, пихая в него сам токен и даты выпуска и протухания
        return TokenDetails.builder()
                .token(token)
                .issuedAt(createdDate)
                .expiresAt(expirationDate)
                .build();
    }

    public Mono<TokenDetails> authenticate(String username, String password) {


        return userService.getUserByUsername(username)
                .flatMap(user -> {
                    if (!user.isEnabled()) {
                        return Mono.error(new AuthException("User is disabled", "GRIGORICH_USER_ACCOUNT_DISABLED"));
                    }
                    if (!passwordEncoder.matches(password, user.getPassword())) {
                        return Mono.error(new AuthException("Invalid password", "GRIGORICH_INVALID_PASSWORD"));
                    }
//                    return Mono.just(new TokenDetails());
                    return Mono.just(generateToken(user).toBuilder()
                            .userId(user.getId())
                            .build());
                })
                .switchIfEmpty(Mono.error(new AuthException("Invalid username", "GRIGORICH_INVALID_USERNAME")));
    }
// video 34.22
}
