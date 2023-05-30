package org.mykola.webfluxsecurity.service;

import lombok.RequiredArgsConstructor;
import org.mykola.webfluxsecurity.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;


}
