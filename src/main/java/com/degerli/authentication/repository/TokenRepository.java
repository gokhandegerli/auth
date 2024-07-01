package com.degerli.authentication.repository;

import com.degerli.authentication.model.Token;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface TokenRepository extends JpaRepository<Token, Integer> {


  @Query("""
      select t from Token t inner join UserEntity u on t.userEntity.id = u.id
      where t.userEntity.id = :userId and t.loggedOut = false
      """)
  List<Token> findAllAccessTokensByUser(Integer userId);

  Optional<Token> findByAccessToken(String tokenEntity);

  Optional<Token> findByRefreshToken(String tokenEntity);
}
