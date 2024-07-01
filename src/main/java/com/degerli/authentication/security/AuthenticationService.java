package com.degerli.authentication.security;


import com.degerli.authentication.dto.LoginRequest;
import com.degerli.authentication.dto.RegisterRequest;
import com.degerli.authentication.model.AuthenticationResponse;
import com.degerli.authentication.model.Role;
import com.degerli.authentication.model.Token;
import com.degerli.authentication.model.UserEntity;
import com.degerli.authentication.repository.TokenRepository;
import com.degerli.authentication.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {

  private final UserRepository repository;
  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;

  private final TokenRepository tokenRepository;

  private final AuthenticationManager authenticationManager;

  public AuthenticationService(UserRepository repository, PasswordEncoder passwordEncoder,
      JwtService jwtService, TokenRepository tokenRepository,
      AuthenticationManager authenticationManager) {
    this.repository = repository;
    this.passwordEncoder = passwordEncoder;
    this.jwtService = jwtService;
    this.tokenRepository = tokenRepository;
    this.authenticationManager = authenticationManager;
  }

  public AuthenticationResponse register(RegisterRequest request) {

    // check if user already exist. if exist than authenticate the user
    if (repository.findByUsername(request.getUsername()).isPresent()) {
      return new AuthenticationResponse(null, null, "User already exist");
    }

    UserEntity userEntity = new UserEntity();
    userEntity.setFirstName(request.getFirstName());
    userEntity.setLastName(request.getLastName());
    userEntity.setUsername(request.getUsername());
    userEntity.setPassword(passwordEncoder.encode(request.getPassword()));


    userEntity.setRole(Role.valueOf(request.getRole()));

    userEntity = repository.save(userEntity);

    String accessToken = jwtService.generateAccessToken(userEntity);
    String refreshToken = jwtService.generateRefreshToken(userEntity);

    saveUserToken(accessToken, refreshToken, userEntity);

    return new AuthenticationResponse(accessToken, refreshToken,
        "User registration was successful");

  }

  public AuthenticationResponse authenticate(LoginRequest request) {
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

    UserEntity userEntity = repository.findByUsername(request.getUsername()).orElseThrow();
    String accessToken = jwtService.generateAccessToken(userEntity);
    String refreshToken = jwtService.generateRefreshToken(userEntity);

    revokeAllTokenByUser(userEntity);
    saveUserToken(accessToken, refreshToken, userEntity);

    return new AuthenticationResponse(accessToken, refreshToken, "User login was successful");

  }

  private void revokeAllTokenByUser(UserEntity userEntity) {
    List<Token> validTokenEntities = tokenRepository.findAllAccessTokensByUser(
        userEntity.getId());
    if (validTokenEntities.isEmpty()) {
      return;
    }

    validTokenEntities.forEach(t -> {
      t.setLoggedOut(true);
    });

    tokenRepository.saveAll(validTokenEntities);
  }

  private void saveUserToken(String accessToken, String refreshToken, UserEntity userEntity) {
    Token token = new Token();
    token.setAccessToken(accessToken);
    token.setRefreshToken(refreshToken);
    token.setLoggedOut(false);
    token.setUser(userEntity);
    tokenRepository.save(token);
  }

  public ResponseEntity refreshToken(HttpServletRequest request,
      HttpServletResponse response) {
    // extract the token from authorization header
    String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      return new ResponseEntity(HttpStatus.UNAUTHORIZED);
    }

    String token = authHeader.substring(7);

    // extract username from token
    String username = jwtService.extractUsername(token);

    // check if the user exist in database
    UserEntity userEntity = repository.findByUsername(username)
        .orElseThrow(() -> new RuntimeException("No user found"));

    // check if the token is valid
    if (jwtService.isValidRefreshToken(token, userEntity)) {
      // generate access token
      String accessToken = jwtService.generateAccessToken(userEntity);
      String refreshToken = jwtService.generateRefreshToken(userEntity);

      revokeAllTokenByUser(userEntity);
      saveUserToken(accessToken, refreshToken, userEntity);

      return new ResponseEntity(
          new AuthenticationResponse(accessToken, refreshToken, "New token generated"),
          HttpStatus.OK);
    }

    return new ResponseEntity(HttpStatus.UNAUTHORIZED);

  }
}
