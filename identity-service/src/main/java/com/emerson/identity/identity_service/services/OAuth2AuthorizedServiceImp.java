package com.emerson.identity.identity_service.services;

import com.emerson.identity.identity_service.entities.oauth2.OAuth2AuthorizationEntity;
import com.emerson.identity.identity_service.repositories.JpaOAuth2AuthorizationRepository;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

@Service(value = "customImplementation")
public class OAuth2AuthorizedServiceImp implements OAuth2AuthorizationService {

    private final JpaOAuth2AuthorizationRepository jpaOAuth2AuthorizationRepository;
    private final RegisteredClientRepository jpaRegisteredClientService;
    private final ObjectMapper mapper = new ObjectMapper();
    public OAuth2AuthorizedServiceImp(RegisteredClientRepository jpaRegisteredClientService,
                                      JpaOAuth2AuthorizationRepository jpaOAuth2AuthorizationRepository){
        Assert.notNull(jpaRegisteredClientService, "jdbcRegisteredClientRepository can not be null");
        Assert.notNull(jpaOAuth2AuthorizationRepository, "jdbcOAuth2AuthorizationRepository can not be null");

        //initialize variables
        this.jpaOAuth2AuthorizationRepository = jpaOAuth2AuthorizationRepository;
        this.jpaRegisteredClientService = jpaRegisteredClientService;

        //Load modules into object mapper
        ClassLoader classLoader = OAuth2AuthorizedServiceImp.class.getClassLoader();
        List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        this.mapper.registerModules(securityModules);
        this.mapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
    }

    @Override
    public void save(OAuth2Authorization authorization){
        Assert.notNull(authorization, "oauth2Authorization can not be null");
        jpaOAuth2AuthorizationRepository.save(toEntity(authorization));
    }

    @Override
    public void remove(OAuth2Authorization authorization){
        Assert.notNull(authorization, "authorization can not be null");
        this.jpaOAuth2AuthorizationRepository.deleteById(authorization.getId());
    }

    @Override
    public OAuth2Authorization findById(String id){
        Assert.notNull(id, "id can not be null");
        return this.jpaOAuth2AuthorizationRepository.findById(id).map(this::toObject).orElse(null);
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType){
        Optional<OAuth2AuthorizationEntity> result;
        if(tokenType == null){
            result = this.jpaOAuth2AuthorizationRepository.findByToken(token);
        }else if(OAuth2ParameterNames.STATE.equals(tokenType.getValue())){
            result = this.jpaOAuth2AuthorizationRepository.findByToken(token);
        }else if(OAuth2ParameterNames.CODE.equals(tokenType.getValue())){
            result = this.jpaOAuth2AuthorizationRepository.findByToken(token);
        }else if(OAuth2ParameterNames.ACCESS_TOKEN.equals(tokenType.getValue())){
            result = this.jpaOAuth2AuthorizationRepository.findByToken(token);
        }else if(OAuth2ParameterNames.REFRESH_TOKEN.equals(tokenType.getValue())){
            result = this.jpaOAuth2AuthorizationRepository.findByToken(token);
        }else{
            result = Optional.empty();
        }
        return result.map(this::toObject).orElse(null);
    }

    private OAuth2Authorization toObject(OAuth2AuthorizationEntity entity){
        RegisteredClient registeredClient = jpaRegisteredClientService.findByClientId(entity.getRegisteredClientId());
        if(registeredClient == null){
            throw new DataRetrievalFailureException(
                    "The registered client with id " + entity.getRegisteredClientId() + " was not found in the database"
            );
        }
        OAuth2Authorization.Builder builder = OAuth2Authorization
                .withRegisteredClient(registeredClient)
                .id(entity.getAuthorizationId())
                .authorizationGrantType(resolveGrantType(entity.getAuthorizationGrantType()))
                .principalName(entity.getPrincipalName())
                .attributes(attributes -> attributes.putAll(parseToMap(entity.getAttributes())));
        if(entity.getAuthorizationCodeValue() != null){
            OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(entity.getAuthorizationCodeValue(), entity.getAuthorizationCodeIssuedAt(), entity.getAuthorizationCodeExpiresAt());
            builder.token(authorizationCode, metadata -> metadata.putAll(parseToMap(entity.getAuthorizationCodeMetadata())));
        }

        if(entity.getAccessTokenValue() != null){
            OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, entity.getAccessTokenValue(), entity.getAccessTokenIssuedAt(), entity.getAccessTokenExpiresAt(), StringUtils.commaDelimitedListToSet(entity.getAccessTokenScopes()));
            builder.token(accessToken, metadata -> metadata.putAll(parseToMap(entity.getAccessTokenMetadata())) );
        }

        if(entity.getRefreshTokenValue() != null){
            OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(entity.getRefreshTokenValue(), entity.getRefreshTokenIssuedAt(), entity.getRefreshTokenExpiresAt());
            builder.token(refreshToken, metadata -> metadata.putAll(parseToMap(entity.getRefreshTokenMetadata())));
        }
        if(entity.getOidcTokenValue() != null){
            OidcIdToken oidcIdToken = new OidcIdToken(entity.getOidcTokenValue(), entity.getOidcTokenIssuedAt(), entity.getOidcTokenExpiresAt(), parseToMap(entity.getOidcTokenMetadata()));
            builder.token(oidcIdToken, metadata -> metadata.putAll(parseToMap(entity.getOidcTokenMetadata())));
        }
        return builder.build();
    }


    private OAuth2AuthorizationEntity toEntity(OAuth2Authorization auth){
        OAuth2AuthorizationEntity entity = OAuth2AuthorizationEntity
                .builder()
                .authorizationId(auth.getId())
                .registeredClientId(auth.getRegisteredClientId())
                .principalName(auth.getPrincipalName())
                .authorizationGrantType(auth.getAuthorizationGrantType().getValue())
                .authorizedScopes(StringUtils.collectionToCommaDelimitedString(auth.getAuthorizedScopes()))
                .attributes(parseToString(auth.getAttributes()))
                .state(auth.getAttribute(OAuth2ParameterNames.STATE))
                .build();

        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = auth.getToken(OAuth2AuthorizationCode.class);
        setTokenValues(authorizationCode, entity::setAuthorizationCodeValue, entity::setAuthorizationCodeIssuedAt,entity::setAuthorizationCodeExpiresAt, entity::setAuthorizationCodeMetadata);

        OAuth2Authorization.Token<OAuth2AccessToken> accessToken = auth.getToken(OAuth2AccessToken.class);
        setTokenValues(accessToken, entity::setAccessTokenValue, entity::setAccessTokenIssuedAt, entity::setAccessTokenExpiresAt, entity::setAccessTokenMetadata);
        if(accessToken != null && accessToken.getToken().getScopes() != null){
            entity.setAccessTokenScopes(StringUtils.collectionToCommaDelimitedString(accessToken.getToken().getScopes()));
        }

        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = auth.getToken(OAuth2RefreshToken.class);
        setTokenValues(refreshToken, entity::setRefreshTokenValue, entity::setRefreshTokenIssuedAt, entity::setRefreshTokenExpiresAt, entity::setRefreshTokenMetadata);

        OAuth2Authorization.Token<OidcIdToken> oidcIdToken = auth.getToken(OidcIdToken.class);
        setTokenValues(oidcIdToken, entity::setOidcTokenValue, entity::setOidcTokenIssuedAt, entity::setOidcTokenExpiresAt, entity::setOidcTokenMetadata);

        if(oidcIdToken != null){
            entity.setOidcTokenClaims(parseToString(oidcIdToken.getClaims()));
        }
        return entity;
    }

    private void  setTokenValues(OAuth2Authorization.Token<?> token ,
                                 Consumer<String> setTokenValue,
                                 Consumer<Instant> setIssuedAt,
                                 Consumer<Instant> setExpirationAt,
                                 Consumer<String> setMetadata)
    {
        if (token != null) {
            setTokenValue.accept(token.getToken().getTokenValue());
            setIssuedAt.accept(token.getToken().getIssuedAt());
            setExpirationAt.accept(token.getToken().getExpiresAt());
            setMetadata.accept(parseToString(token.getMetadata()));
        }
    }

    private AuthorizationGrantType resolveGrantType(String authorizationGrantType){
        if(AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(authorizationGrantType)){
            return AuthorizationGrantType.AUTHORIZATION_CODE;
        }else if(AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(authorizationGrantType)){
            return AuthorizationGrantType.REFRESH_TOKEN;
        }else if(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(authorizationGrantType)){
            return AuthorizationGrantType.CLIENT_CREDENTIALS;
        }
        return new AuthorizationGrantType(authorizationGrantType);//custom grant type
    }


    //this is how we can store Map<?,? > objects in the database as strings and parse them back when we read from the database again
    private String parseToString(Map<String, Object> attributes){
        try{
            return this.mapper.writeValueAsString(attributes);
        }catch (Exception e){
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }
    private Map<String, Object>  parseToMap(String attributes){
        try{
            return this.mapper.readValue(attributes, new TypeReference<Map<String, Object>>(){});
        }catch (Exception ex){
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }

}
