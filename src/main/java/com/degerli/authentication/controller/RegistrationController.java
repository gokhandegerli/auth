package com.degerli.authentication.controller;

import com.degerli.authentication.model.MyUser;
import com.degerli.authentication.repository.MyUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class RegistrationController {

  private MyUserRepository myUserRepository;
  private PasswordEncoder passwordEncoder;

  @PostMapping("/register/user")
  public MyUser createUser(
      @RequestBody
      MyUser user) {
    user.setPassword(passwordEncoder.encode(user.getPassword()));
    return myUserRepository.save(user);
  }
}