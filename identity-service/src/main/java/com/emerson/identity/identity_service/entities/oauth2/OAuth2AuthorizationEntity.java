package com.emerson.identity.identity_service.entities.oauth2;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "oauth2_authorizations")
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class OAuth2AuthorizationEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;
    @Column(columnDefinition = "CHAR(36)")
    private String authorizationId;
    private String registeredClientId;
    private String principalName;
    private String authorizationGrantType;
    private String authorizedScopes;
    @Lob
    @Column(name = "attributes", columnDefinition = "text")
    private String attributes;
    @Column(name = "state", columnDefinition = "text")
    private String state;

    @Lob
    @Column(name = "authorization_code_value", columnDefinition = "text")
    private String authorizationCodeValue;
    private Instant authorizationCodeIssuedAt;
    private Instant authorizationCodeExpiresAt;
    @Lob
    @Column(name = "authorization_code_metadata", columnDefinition = "text")
    private String authorizationCodeMetadata;


    @Lob
    @Column(name = "access_token_value",  columnDefinition = "text")
    private String accessTokenValue;
    private Instant accessTokenIssuedAt;
    private Instant accessTokenExpiresAt;
    @Lob
    @Column(name = "access_token_metadata", columnDefinition = "text")
    private String accessTokenMetadata;
    private String accessTokenType;
    private String accessTokenScopes;


    @Lob
    @Column(name =  "oidc_token_value",  columnDefinition = "text")
    private String oidcTokenValue;
    private Instant  oidcTokenIssuedAt;
    private Instant oidcTokenExpiresAt;
    @Lob
    @Column(name =  "oidc_token_metadata", columnDefinition = "text")
    private String oidcTokenMetadata;
    @Lob
    @Column(name =  "oidc_token_claims", columnDefinition = "text")
    private String oidcTokenClaims;


    @Lob
    @Column(name = "refresh_token_value",  columnDefinition = "text")
    private String refreshTokenValue;
    private Instant refreshTokenIssuedAt;
    private Instant refreshTokenExpiresAt;
    @Lob
    @Column(name = "refresh_token_metadata", columnDefinition = "text")
    private String refreshTokenMetadata;


    @Lob
    @Column(name = "user_code_value",  columnDefinition = "text")
    private String userCodeValue;
    private Instant userCodeIssuedAt;
    private Instant userCodeExpiresAt;
    @Lob
    @Column(name = "user_code_metadata", columnDefinition = "text")
    private String userCodeMetadata;


    @Lob
    @Column(name = "device_code_value",  columnDefinition = "text")
    private String deviceCodeValue;
    private Instant deviceCodeIssuedAt;
    private Instant deviceCodeExpiresAt;
    @Lob
    @Column(name = "device_code_metadata", columnDefinition = "text")
    private String deviceCodeMetadata;


}
