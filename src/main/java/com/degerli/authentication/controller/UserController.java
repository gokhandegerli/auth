package com.degerli.authentication.controller;

import com.degerli.authentication.model.UserEntity;
import com.degerli.authentication.dto.UserRequest;
import com.degerli.authentication.dto.UserResponse;
import com.degerli.authentication.mapper.UserMapper;
import com.degerli.authentication.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {
  private final UserService userService;
  private final UserMapper userMapper;

  @PostMapping("/register")
  public ResponseEntity<UserResponse> registerUser(
      @Validated
      @RequestBody
      UserRequest userRequest) {
    UserEntity user = userService.registerUser(userMapper.toEntity(userRequest));
    return ResponseEntity.ok(userMapper.toResponse(user));
  }

  @GetMapping("/{username}")
  public ResponseEntity<UserResponse> getUser(
      @PathVariable
      String username) {
    UserEntity user = userService.findByUsername(username);
    if (user == null) {
      return ResponseEntity.notFound().build();
    }
    return ResponseEntity.ok(userMapper.toResponse(user));
  }
}