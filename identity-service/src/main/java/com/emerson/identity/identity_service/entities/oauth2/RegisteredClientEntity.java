package com.emerson.identity.identity_service.entities.oauth2;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.time.Instant;

@Entity
@Table(name = "registered_clients")
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@ToString
@Builder
public class RegisteredClientEntity implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;
    @Column(length = 1000)
    private String clientId;
    private Instant clientIdIssuedAt;
    private Instant clientIdExpiresAt;
    @Column(length = 1000)
    private String clientSecret;
    private Instant clientSecretExpiresAt;
    @Column(length = 1000)
    private String clientName;

    @Column(name = "client_authentication_methods", length = 1000)
    private String clientAuthenticationMethods;
    @Column(name = "authorization_grant_types", length = 1000)
    private String authorizationGrantTypes;
    @Column(length = 1000)
    private String redirectUris;
    @Column(length = 1000)
    private String postLogoutRedirectUris;
    @Column(length = 1000)
    private String scopes;
    @Column(length = 1000)
    private String clientSettings;
    @Column(length = 1000)
    private String tokenSettings;
    /*
    @Lob
    @Column(name = "client_settings", columnDefinition = "BLOB")
    private byte[] clientSettings;
    @Lob
    @Column(name = "token_settings", columnDefinition = "BLOB")
    private byte[] tokenSettings;

     */
}
