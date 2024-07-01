package com.degerli.authentication.controller;

import com.degerli.authentication.config.CustomLogoutHandler;
import com.degerli.authentication.dto.LoginRequest;
import com.degerli.authentication.dto.RegisterRequest;
import com.degerli.authentication.model.AuthenticationResponse;
import com.degerli.authentication.model.UserEntity;
import com.degerli.authentication.security.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthenticationController {

  private final AuthenticationService authService;
  private final CustomLogoutHandler customLogoutHandler;

  public AuthenticationController(AuthenticationService authService,
      CustomLogoutHandler customLogoutHandler) {
    this.authService = authService;
    this.customLogoutHandler = customLogoutHandler;
  }


  @PostMapping("/register")
  public ResponseEntity<AuthenticationResponse> register(
      @RequestBody
      RegisterRequest request) {
    return ResponseEntity.ok(authService.register(request));
  }

  @PostMapping("/login")
  public ResponseEntity<AuthenticationResponse> login(
      @RequestBody
      LoginRequest request) {
    return ResponseEntity.ok(authService.authenticate(request));
  }

  @PostMapping("/refresh_token")
  public ResponseEntity refreshToken(HttpServletRequest request,
      HttpServletResponse response) {
    return authService.refreshToken(request, response);
  }

  @PostMapping("/logout")
  public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) {
    customLogoutHandler.logout(request, response, authentication);
    return ResponseEntity.noContent().build();
  }


}
