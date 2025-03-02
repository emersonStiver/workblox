package com.emerson.oauth2client.services;

import io.r2dbc.spi.Parameter;
import io.r2dbc.spi.Parameters;
import io.r2dbc.spi.Readable;
import io.r2dbc.spi.Type;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.r2dbc.core.DatabaseClient.GenericExecuteSpec;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;
import java.util.function.BiFunction;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
public class AuthorizedClientServiceImp implements ReactiveOAuth2AuthorizedClientService {

    private final ReactiveClientRegistrationRepository clientRegistrationRepository;
    private final DatabaseClient databaseClient;

    private static final String COLUMN_NAMES =
            "client_registration_id, " +
            "principal_name, " +
            "access_token_type, " +
            "access_token_value, " +
            "access-token_issued_at, " +
            "access_token_expires_at," +
            "access_token_scopes, " +
            "refresh_token_value, " +
            "refresh_token_issued_at";
    private static final String PRIMARY_KEY_FILTER = "client_registration_id = :clientRegistrationId AND principal_name = :principalName";
    private static final String TABLE_NAME = "oauth2_authorized_clients";
    private static final String LOAD_AUTHORIZED_CLIENT_SQL = "SELECT " +  COLUMN_NAMES + " FROM " + TABLE_NAME + " WHERE " + PRIMARY_KEY_FILTER;

    private static final String SAVED_AUTHORIZED_CLIENT_SQL = "INSERT INTO " + TABLE_NAME + " ("+COLUMN_NAMES+") " +
            "VALUES ( " +
                ":clientRegistrationId, :principalName, " +
                ":accessTokenType, :accessTokenValue, :accessTokenIssuedAt, :accessTokenExpiresAt, :accessTokenScopes, " +
                " :refreshTokenValue, :refreshTokenIssuedAt" +
            ")";

    private static final String REMOVE_AUTHORIZED_CLIENT_SQL = "DELETE FROM " + TABLE_NAME +  " WHERE " + PRIMARY_KEY_FILTER;

    private static final String UPDATE_AUTHORIZED_CLIENT_SQL = "UPDATE "+ TABLE_NAME + " SET " +
                    "access_token_type = :accessTokenType, " +
                    " access_token_value = :accessTokenValue, " +
                    " access_token_issued_at = :accessTokenIssuedAt," +
                    " access_token_expires_at = :accessTokenExpiresAt, " +
                    " access_token_scopes = :accessTokenScopes," +
                    " refresh_token_value = :refreshTokenValue, " +
                    " refresh_token_issued_at = :refreshTokenIssuedAt" +
                    " WHERE " + PRIMARY_KEY_FILTER;


    @Override
    public <T extends OAuth2AuthorizedClient> Mono<T> loadAuthorizedClient(String clientRegistrationId, String principalName){
        return  this.databaseClient.sql(LOAD_AUTHORIZED_CLIENT_SQL)
                .bind("clientRegistrationId", clientRegistrationId)
                .bind("principalName", principalName)
                .map(rowMapperToLoadAuthorizedClientFromDb(clientRegistrationId, principalName))
                .first()
                .flatMap(context -> clientRegistrationRepository
                            .findByRegistrationId(context.getClientRegistrationId())
                            .switchIfEmpty(
                                    Mono.error(new DataRetrievalFailureException("The ClientRegistration with id '" + clientRegistrationId
                                            + "' exists in the data source, however, it was not found in the ReactiveClientRegistrationRepository."))
                            )
                        .map(clientRegistration -> (T) createAuthorizedClient(clientRegistration, context))

                );
    }

    @Override
    public Mono<Void> saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal){
        Assert.hasText(authorizedClient.getClientRegistration().getRegistrationId(), "clientRegistrationid can not be null");
        Assert.hasText(authorizedClient.getPrincipalName(), "principalName can not be null");

        return loadAuthorizedClient(authorizedClient.getClientRegistration().getRegistrationId(), authorizedClient.getPrincipalName())
                .flatMap(ifAuthorizedClientExists -> {
                    GenericExecuteSpec executeSpec = this.databaseClient.sql(UPDATE_AUTHORIZED_CLIENT_SQL);
                    for(var entry : this.authorizedClientToMap.apply(authorizedClient, principal) ){
                        executeSpec = executeSpec.bind(entry.getKey(), entry.getValue());
                    }
                    return executeSpec.fetch().rowsUpdated().then();
                })
                .switchIfEmpty(Mono.defer(()-> {
                    /* If we used switchIfEmpty(insertAuthorizedClient(authorizedClient, principal)) directly, insertAuthorizedClient(...) would be evaluated immediately,
                       even if it's not needed. With Mono.defer(...), the method is only called when needed, avoiding unnecessary execution. */
                    GenericExecuteSpec executeSpec = this.databaseClient.sql(SAVED_AUTHORIZED_CLIENT_SQL);
                    for(var entry : authorizedClientToMap.apply(authorizedClient, principal)){
                        executeSpec.bind(entry.getKey(), entry.getValue());
                    }
                    return executeSpec.fetch().rowsUpdated().then();
                }))
                .then();
    }

    @Override
    public Mono<Void> removeAuthorizedClient(String clientRegistrationId, String principalName){
        Assert.hasText(clientRegistrationId, "clientRegistrationId can not be null");
        Assert.hasText(principalName, "principalName can not be null");
        return databaseClient.sql(REMOVE_AUTHORIZED_CLIENT_SQL).bind("clientRegistrationId", clientRegistrationId).bind("principalName", principalName).then();
    }


    private BiFunction<OAuth2AuthorizedClient, Authentication, Set<Map.Entry<String, Parameter>>> authorizedClientToMap = (au, pr) -> {
        Map<String, Parameter> params = new HashMap<>();
        final OAuth2AccessToken accessToken = au.getAccessToken();
        final OAuth2RefreshToken refreshToken = au.getRefreshToken();

        params.put("clientRegistrationId", Parameters.in(au.getClientRegistration().getRegistrationId()));
        params.put("principalName", Parameters.in(au.getPrincipalName()));

        params.put("accessTokenType", Parameters.in(accessToken.getTokenType().getValue()));
        params.put("accessTokenValue", Parameters.in(accessToken.getTokenValue()));
        params.put("accessTokenIssuedAt", Parameters.in(LocalDateTime.ofInstant(accessToken.getIssuedAt(), ZoneOffset.UTC)));
        params.put("accessTokenExpiredAt", Parameters.in(LocalDateTime.ofInstant(accessToken.getExpiresAt(), ZoneOffset.UTC)));

        String accessTokenScopes = null;
        if(!CollectionUtils.isEmpty(accessToken.getScopes())){
            accessTokenScopes = StringUtils.collectionToDelimitedString(accessToken.getScopes(), ",");
        }
        params.put("accessTokenScopes", Parameters.in(accessTokenScopes));

        String refreshTokenValue = Optional.ofNullable(refreshToken).map(OAuth2RefreshToken::getTokenValue).orElse(null);
        LocalDateTime refreshTokenIssuedAt = Optional.ofNullable(refreshToken)
                .map(OAuth2RefreshToken::getIssuedAt)
                .map(instant -> LocalDateTime.ofInstant(instant, ZoneOffset.UTC))
                .orElse(null);
        params.put("refreshTokenValue", Parameters.in(refreshTokenValue));
        params.put("refreshTokenIssuedAt", Parameters.in(refreshTokenIssuedAt));
        return params.entrySet();
    };


    private Function<Readable, OAuth2AuthorizedClientContext> rowMapperToLoadAuthorizedClientFromDb(String clientRegistrationId, String principalName){
        return (Readable row) ->  {
            String cR = row.get("client_registration_id", String.class);
            String pN = row.get("principal_name", String.class);
            OAuth2AccessToken.TokenType tokenType = null;
            if(row.get("access_token_type", String.class).equalsIgnoreCase(OAuth2AccessToken.TokenType.BEARER.getValue())){
                tokenType = OAuth2AccessToken.TokenType.BEARER;
            }
            String accessTokenValue = row.get("access_token_value", String.class);
            Instant issuedAt = row.get("access_token_issued_at", LocalDateTime.class).toInstant(ZoneOffset.UTC);
            Instant expiresAt = row.get("access_token_expires_at", LocalDateTime.class).toInstant(ZoneOffset.UTC);

            Set<String> accessTokenScopes = Collections.emptySet();
            String scopes = row.get("access_token_scopes", String.class);
            if(scopes != null){
                accessTokenScopes = StringUtils.commaDelimitedListToSet(scopes);
            }
            final OAuth2AccessToken accessToken = new OAuth2AccessToken(tokenType, accessTokenValue, issuedAt, expiresAt);

            OAuth2RefreshToken refreshToken = null;
            String refreshTokenValue = row.get("refresh_token_value", String.class);

            if(refreshTokenValue != null){
                LocalDateTime refreshTokenIssuedAt = row.get("refresh_token_issued_at", LocalDateTime.class);
                if(refreshTokenIssuedAt != null){
                    issuedAt = refreshTokenIssuedAt.toInstant(ZoneOffset.UTC);
                }
                refreshToken = new OAuth2RefreshToken(refreshTokenValue, issuedAt);
            }
            return new OAuth2AuthorizedClientContext(clientRegistrationId, principalName,accessToken, refreshToken);
        };
    }

    private <T extends OAuth2AuthorizedClient> T createAuthorizedClient(ClientRegistration clientRegistration, OAuth2AuthorizedClientContext context) {
        return (T) new OAuth2AuthorizedClient(clientRegistration, context.getPrincipalName(), context.getAccessToken(), context.getRefreshToken());
    }

    @Getter
    private final class OAuth2AuthorizedClientContext {
        private final String clientRegistrationId;
        private final String principalName;
        private final OAuth2AccessToken accessToken;
        private final OAuth2RefreshToken refreshToken;
        public OAuth2AuthorizedClientContext(OAuth2AuthorizedClient authorizedClient, Authentication principal){
            Assert.notNull(authorizedClient, "authorizedClient cannot be null");
            Assert.notNull(principal, "principal cannot be null");
            this.clientRegistrationId = authorizedClient.getClientRegistration().getRegistrationId();
            this.principalName = principal.getName();
            this.accessToken = authorizedClient.getAccessToken();
            this.refreshToken = authorizedClient.getRefreshToken();
        }

        public OAuth2AuthorizedClientContext(String clientRegistrationId, String principalName,
                                            OAuth2AccessToken accessToken, OAuth2RefreshToken refreshToken) {
            Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
            Assert.hasText(principalName, "principalName cannot be empty");
            Assert.notNull(accessToken, "accessToken cannot be null");
            this.clientRegistrationId = clientRegistrationId;
            this.principalName = principalName;
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
        }


    }
}
