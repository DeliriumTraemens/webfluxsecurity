package org.mykola.webfluxsecurity.security;

import lombok.RequiredArgsConstructor;
import org.mykola.webfluxsecurity.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class SecurityService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

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

}
