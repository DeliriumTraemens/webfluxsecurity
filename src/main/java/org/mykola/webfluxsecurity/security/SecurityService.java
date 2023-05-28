package org.mykola.webfluxsecurity.security;

import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import org.mykola.webfluxsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Date;
import java.util.Map;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class SecurityService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${jwt.secret}")
    private String secret;
    @Value("${jwt.expiration}")
    private Integer expirationInSeconds;
    @Value("${jwt.issuer}")
    private String issuer;

    private TokenDetails generateToken(Date expirationDate, Map<String, Object> claims, String subject){

        Date createdDate = new Date();
        String token = Jwts.builder()
                    .setClaims(claims)
                    .setIssuer(issuer)
                    .setSubject(subject)
                    .setIssuedAt(createdDate)
                    .setId(UUID.randomUUID().toString())
                    .setExpiration(expirationDate)
                .compact();

        return TokenDetails.builder()
                    .token(token)
                    .issuedAt(createdDate)
                    .expiresAt(expirationDate)
                .build();
    }

    public Mono<TokenDetails> authenticate(String username, String password){


        return userRepository.findByUserName(username)
                .flatMap(user ->{
                        if(!user.isEnabled()){
                            return Mono.error(new RuntimeException("User is not enabled"));
                        }
                        if(!passwordEncoder.matches(password,user.getPassword())){
                            return Mono.error(new RuntimeException("User password is incorrect"));
                        }
                    return Mono.just(new TokenDetails());
                })
                .switchIfEmpty(Mono.error(new RuntimeException("Username not found")));
    }
// video 34.22
}
