package com.degerli.authentication.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class UserRequest {
  @NotBlank
  private String username;

  @NotBlank
  private String password;

  @Email
  @NotBlank
  private String email;

  @NotBlank
  private String role;
}