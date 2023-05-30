package org.mykola.webfluxsecurity.rest;

import lombok.RequiredArgsConstructor;
import org.mykola.webfluxsecurity.dto.AuthRequestDto;
import org.mykola.webfluxsecurity.dto.AuthResponseDto;
import org.mykola.webfluxsecurity.dto.UserDto;
import org.mykola.webfluxsecurity.entity.UserEntity;
import org.mykola.webfluxsecurity.mapper.UserMapper;
import org.mykola.webfluxsecurity.repository.UserRepository;
import org.mykola.webfluxsecurity.security.CustomPrincipal;
import org.mykola.webfluxsecurity.security.SecurityService;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
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
    public Mono<AuthResponseDto> login(@RequestBody AuthRequestDto dto) {
        return securityService.authenticate(dto.getUsername(), dto.getPassword())
                .flatMap(tokenDetails -> Mono.just(AuthResponseDto.builder()
                        .userId(tokenDetails.getUserId())
                        .token(tokenDetails.getToken())
                        .issuedAt(tokenDetails.getIssuedAt())
                        .expiresAt(tokenDetails.getExpiresAt())
                        .build()));
    }

    @GetMapping("/info")
    public Mono<UserDto>getUserInfo(Authentication authentication){
        CustomPrincipal customPrincipal = (CustomPrincipal) authentication.getPrincipal();
        return userRepository.findById(customPrincipal.getId())
                .map(userMapper::map);
    }


}
