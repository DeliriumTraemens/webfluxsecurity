package org.mykola.webfluxsecurity.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.mykola.webfluxsecurity.entity.UserEntity;
import org.mykola.webfluxsecurity.entity.UserRole;
import org.mykola.webfluxsecurity.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public Mono<UserEntity>registerUser(UserEntity user){
        return userRepository.save(
                user.toBuilder()
                .password(passwordEncoder.encode(user.getPassword()))
                .role(UserRole.USER)
                .enabled(true)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build()
        ).doOnSuccess(u->{
            log.info("IN registerUser User: {} created", u);
        });
    }

    public Mono<UserEntity>getUserById(Long id){
        return userRepository.findById(id);
    }

    public Mono<UserEntity> getUserByUsername(String username){
        return userRepository.findByUsername(username);
    }

}
