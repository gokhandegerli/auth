package com.degerli.authentication.dto;

import lombok.Data;

@Data
public class RegisterRequest {

  private String firstName;
  private String lastName;
  private String username;
  private String password;
  private String role;

}
