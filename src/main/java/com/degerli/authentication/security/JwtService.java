package com.degerli.authentication.security;

import com.degerli.authentication.model.UserEntity;
import com.degerli.authentication.repository.TokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.util.Date;
import java.util.function.Function;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

  @Value("${application.security.jwt.secret-key}")
  private String secretKey;

  @Value("${application.security.jwt.access-token-expiration}")
  private long accessTokenExpire;

  @Value("${application.security.jwt.refresh-token-expiration}")
  private long refreshTokenExpire;


  private final TokenRepository tokenRepository;

  public JwtService(TokenRepository tokenRepository) {
    this.tokenRepository = tokenRepository;
  }

  public String extractUsername(String token) {
    return extractClaim(token, Claims::getSubject);
  }


  public boolean isValid(String token, UserDetails user) {
    String username = extractUsername(token);

    boolean validToken = tokenRepository.findByAccessToken(token)
        .map(t -> !t.isLoggedOut())
        .orElse(false);

    return (username.equals(user.getUsername())) && !isTokenExpired(token) && validToken;
  }

  public boolean isValidRefreshToken(String token, UserEntity userEntity) {
    String username = extractUsername(token);

    boolean validRefreshToken = tokenRepository.findByRefreshToken(token)
        .map(t -> !t.isLoggedOut())
        .orElse(false);

    return (username.equals(userEntity.getUsername())) && !isTokenExpired(token)
        && validRefreshToken;
  }

  private boolean isTokenExpired(String token) {
    return extractExpiration(token).before(new Date());
  }

  private Date extractExpiration(String token) {
    return extractClaim(token, Claims::getExpiration);
  }

  public <T> T extractClaim(String token, Function<Claims, T> resolver) {
    Claims claims = extractAllClaims(token);
    return resolver.apply(claims);
  }

  private Claims extractAllClaims(String token) {
    return Jwts.parser()
        .verifyWith(getSigningKey())
        .build()
        .parseSignedClaims(token)
        .getPayload();
  }


  public String generateAccessToken(UserEntity userEntity) {
    return generateToken(userEntity, accessTokenExpire);
  }

  public String generateRefreshToken(UserEntity userEntity) {
    return generateToken(userEntity, refreshTokenExpire);
  }

  private String generateToken(UserEntity userEntity, long expireTime) {
    String token = Jwts.builder()
        .subject(userEntity.getUsername())
        .issuedAt(new Date(System.currentTimeMillis()))
        .expiration(new Date(System.currentTimeMillis() + expireTime))
        .signWith(getSigningKey())
        .compact();

    return token;
  }

  private SecretKey getSigningKey() {
    byte[] keyBytes = Decoders.BASE64URL.decode(secretKey);
    return Keys.hmacShaKeyFor(keyBytes);
  }
}
