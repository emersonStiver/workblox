package com.emerson.oauth2client.services;

import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistration.ProviderDetails;
import org.springframework.security.oauth2.client.registration.ClientRegistration.ProviderDetails.UserInfoEndpoint;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.stereotype.Service;
import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Set;

//@Service
//@RequiredArgsConstructor
public class ClientRegistrationServiceImp implements ReactiveClientRegistrationRepository {

    private  DatabaseClient databaseClient;

    private final String LOAD_CLIENT_REGISTRATION = """
        SELECT registration_id, client_id, client_secret, authentication_method, authorization_grant_type, 
               redirect_uri, scopes, client_name, authorization_uri, token_uri, 
               user_info_uri, user_info_authentication_method, jwk_set_uri, issuer_uri
        FROM client_registrations 
        WHERE registration_id = :registrationId
    """;

    private final String SAVE_CLIENT_REGISTRATION = """
        INSERT INTO client_registrations (registration_id, client_id, client_secret, authentication_method, 
                                          authorization_grant_type, redirect_uri, scopes, client_name,
                                          authorization_uri, token_uri, user_info_uri, user_info_authentication_method, 
                                          jwk_set_uri, issuer_uri) 
        VALUES (:registrationId, :clientId, :clientSecret, :authenticationMethod, 
                :authorizationGrantType, :redirectUri, :scopes, :clientName, 
                :authorizationUri, :tokenUri, :userInfoUri, :userInfoAuthenticationMethod, 
                :jwkSetUri, :issuerUri)
        ON DUPLICATE KEY UPDATE 
            client_id = VALUES(client_id),
            client_secret = VALUES(client_secret),
            authentication_method = VALUES(authentication_method),
            authorization_grant_type = VALUES(authorization_grant_type),
            redirect_uri = VALUES(redirect_uri),
            scopes = VALUES(scopes),
            client_name = VALUES(client_name),
            authorization_uri = VALUES(authorization_uri),
            token_uri = VALUES(token_uri),
            user_info_uri = VALUES(user_info_uri),
            user_info_authentication_method = VALUES(user_info_authentication_method),
            jwk_set_uri = VALUES(jwk_set_uri),
            issuer_uri = VALUES(issuer_uri)
    """;

    @Override
    public Mono<ClientRegistration> findByRegistrationId(String registrationId) {
        return databaseClient.sql(LOAD_CLIENT_REGISTRATION)
                .bind("registrationId", registrationId)
                .map(row -> {
                    return ClientRegistration
                            .withRegistrationId(row.get("registration_id", String.class))
                            .clientId(row.get("client_id", String.class))
                            .clientSecret(row.get("client_secret", String.class))
                            .clientAuthenticationMethod(new ClientAuthenticationMethod(row.get("authentication_method", String.class)))
                            .authorizationGrantType(new AuthorizationGrantType(row.get("authorization_grant_type", String.class)))
                            .redirectUri(row.get("redirect_uri", String.class))
                            .scope(StringUtils.commaDelimitedListToSet(row.get("scopes", String.class)))
                            .clientName(row.get("client_name", String.class))
                            // Provider details
                            .authorizationUri(row.get("authorization_uri", String.class))
                            .tokenUri(row.get("token_uri", String.class))
                            .jwkSetUri(row.get("jwk_set_uri", String.class))
                            .issuerUri(row.get("issuer_uri", String.class))
                            //User info details
                            .userInfoUri(row.get("user_info_uri", String.class))
                            .userInfoAuthenticationMethod(new AuthenticationMethod(row.get("user_info_authentication_method", String.class)))
                            .build();
                }).first();
    }
    public Mono<List<ClientRegistration>> getAllRegisteredClients(){
        return null;
    }

    public Mono<Void> saveClientRegistration(ClientRegistration registration) {
        UserInfoEndpoint userInfoEndpoint = registration.getProviderDetails().getUserInfoEndpoint();
        ProviderDetails p = registration.getProviderDetails();

        return databaseClient.sql(SAVE_CLIENT_REGISTRATION)
                .bind("registrationId", registration.getRegistrationId())
                .bind("clientId", registration.getClientId())
                .bind("clientSecret", registration.getClientSecret())
                .bind("authenticationMethod", registration.getClientAuthenticationMethod().getValue())
                .bind("authorizationGrantType", registration.getAuthorizationGrantType().getValue())
                .bind("redirectUri", registration.getRedirectUri())
                .bind("scopes", String.join(",", registration.getScopes()))
                .bind("clientName", registration.getClientName())

                // Provider details
                .bind("authorizationUri", p.getAuthorizationUri())
                .bind("tokenUri", p.getTokenUri())
                .bind("userInfoUri", userInfoEndpoint.getUri())
                .bind("jwkSetUri", p.getJwkSetUri())
                .bind("issuerUri", p.getIssuerUri())

                //User info details
                .bind("userInfoAuthenticationMethod", userInfoEndpoint.getAuthenticationMethod().getValue())
                .bind("user_info_authentication_method", userInfoEndpoint.getAuthenticationMethod().getValue())
                .then();
    }
}

