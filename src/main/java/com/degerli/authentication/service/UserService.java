package com.degerli.authentication.service;

import com.degerli.authentication.model.UserEntity;
import com.degerli.authentication.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;

  public UserEntity registerUser(UserEntity user) {
    user.setPassword(passwordEncoder.encode(user.getPassword()));
    return userRepository.save(user);
  }

  public UserEntity findByUsername(String username) {
    return userRepository.findByUsername(username).orElse(null);
  }
}