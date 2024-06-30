package com.degerli.authentication.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
public class JwtTokenProvider {

  @Value("${jwt.secret}")
  private String jwtSecret;

  @Value("${jwt.expiration}")
  private Long jwtExpirationInMs;

  public JwtTokenProvider(
      @Value("${jwt.secret}") String jwtSecret,
      @Value("${jwt.expiration}") Long jwtExpirationInMs) {
    this.jwtSecret = jwtSecret;
    this.jwtExpirationInMs = jwtExpirationInMs;
  }

  private final Key key = Keys.hmacShaKeyFor(jwtSecret.getBytes());

  public String generateToken(Authentication authentication) {
    CustomUserDetails userPrincipal = (CustomUserDetails) authentication.getPrincipal();

    Date now = new Date();
    Date expiryDate = new Date(now.getTime() + jwtExpirationInMs);

    return Jwts.builder()
        .setSubject(userPrincipal.getUsername())
        .setIssuedAt(new Date())
        .setExpiration(expiryDate)
        .signWith(key, SignatureAlgorithm.HS512)
        .compact();
  }

  public String getUserUsernameFromJWT(String token) {
    Claims claims = Jwts.parserBuilder()
        .setSigningKey(key)
        .build()
        .parseClaimsJws(token)
        .getBody();

    return claims.getSubject();
  }

  public boolean validateToken(String authToken) {
    try {
      Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(authToken);
      return true;
    } catch (Exception e) {
      return false;
    }
  }
}