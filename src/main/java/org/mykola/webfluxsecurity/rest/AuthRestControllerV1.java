package org.mykola.webfluxsecurity.rest;

import lombok.RequiredArgsConstructor;
import org.mykola.webfluxsecurity.dto.AuthRequestDto;
import org.mykola.webfluxsecurity.dto.UserDto;
import org.mykola.webfluxsecurity.entity.UserEntity;
import org.mykola.webfluxsecurity.mapper.UserMapper;
import org.mykola.webfluxsecurity.repository.UserRepository;
import org.mykola.webfluxsecurity.security.SecurityService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthRestControllerV1 {
    private final SecurityService securityService;
    private final UserRepository userRepository;
    private final UserMapper userMapper;

    @PostMapping("/register")
    public Mono<UserDto> register(@RequestBody UserDto dto) {
        UserEntity entity = userMapper.map(dto);
        return userRepository.save(entity).map(userMapper::map);
    }

    @PostMapping("/login")
    public Mono<AuthRequestDto> login(@RequestBody AuthRequestDto authRequestDto) {

    }


}
