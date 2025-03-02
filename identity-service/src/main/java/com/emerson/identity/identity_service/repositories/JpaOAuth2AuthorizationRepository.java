package com.emerson.identity.identity_service.repositories;

import com.emerson.identity.identity_service.entities.oauth2.OAuth2AuthorizationEntity;
import io.lettuce.core.dynamic.annotation.Param;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface JpaOAuth2AuthorizationRepository extends JpaRepository<OAuth2AuthorizationEntity, String> {
    @Query(value = "SELECT * FROM oauth2_authorizations WHERE " +
            "state = :token " +
            "OR access_token_value = :token " +
            "OR authorization_token_value = :token " +
            "OR refresh_token_value = :token", nativeQuery = true)
    Optional<OAuth2AuthorizationEntity> findByToken(@Param("token") String token);

    Optional<OAuth2AuthorizationEntity> findByAccessToken(@Param("access_token") String access_token);
    Optional<OAuth2AuthorizationEntity> findByRefreshTokenValue(String refreshTokenValue);
    Optional<OAuth2AuthorizationEntity> findByAuthorizationCodeValue(String authorizationCodeValue);
    Optional<OAuth2AuthorizationEntity> findByState(String state);
}
