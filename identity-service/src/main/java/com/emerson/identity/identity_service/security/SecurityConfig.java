package com.emerson.identity.identity_service.security;

import com.emerson.identity.identity_service.controllers.dtos.RsaKeyPairDto;
import com.emerson.identity.identity_service.entities.signingKeys.RsaKeyPair;
import com.emerson.identity.identity_service.repositories.JpaOAuth2AuthorizationRepository;
import com.emerson.identity.identity_service.repositories.JpaRegisteredClientRepository;
import com.emerson.identity.identity_service.repositories.JpaUserDetailsRepository;
import com.emerson.identity.identity_service.services.OAuth2AuthorizedServiceImp;
import com.emerson.identity.identity_service.services.RegisteredClientServiceImp;
import com.emerson.identity.identity_service.services.contracts.RsaKeyPairService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Configuration
@AllArgsConstructor
@EnableWebSecurity
@Import (OAuth2AuthorizationServerConfiguration.class)
public class SecurityConfig {

    private final JpaRegisteredClientRepository registeredClientRepository;
    private final ObjectMapper mapper;
    private final JpaOAuth2AuthorizationRepository oauth2AuthorizationRepository;
    private final RegisteredClientRepository registeredClientService;
    private final UserDetailsManager userDetailsManagerService;
    private final RsaKeyPairService rsaKeyPairService;

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception{

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer.authorizationServer();

        http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, (authServer) -> {
                    authServer.authorizationService(oAuth2AuthorizationService());
                     authServer.authorizationEndpoint(Customizer.withDefaults());


                });

        http.exceptionHandling(ex -> {
            ex.defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint("/login"),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
            );
        });

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain standardSecurityFilterChain(HttpSecurity http) throws Exception{

        http.userDetailsService(userDetailsManagerService);
        http.csrf(csrfConfigurer -> csrfConfigurer.disable());

        http.formLogin(formLoginConfigurer -> {
            formLoginConfigurer.successHandler(new MFAAuthenticationSuccessHandler("/twoFactorAuthentication", "CREDENTIALS_AUTHENTICATED"));
            formLoginConfigurer.failureHandler(new SimpleUrlAuthenticationFailureHandler("/logout?error"));
        });

        http.authorizeHttpRequests( authorizeHttpRequestConfigurer -> {
            authorizeHttpRequestConfigurer.requestMatchers("/error", "/login").permitAll();
            authorizeHttpRequestConfigurer.requestMatchers("/twoFactorAuthentication").hasAuthority("CREDENTIALS_AUTHENTICATED");
            authorizeHttpRequestConfigurer.anyRequest().authenticated();
        });

        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(){
        return new RegisteredClientServiceImp(registeredClientRepository, mapper);
    }
    @Bean
    public OAuth2AuthorizationService oAuth2AuthorizationService(){
        return new OAuth2AuthorizedServiceImp(registeredClientService ,oauth2AuthorizationRepository);
    }

    @Bean
    public AuthenticationSuccessHandler getAuthenticationSuccessHandler(){
        return new SavedRequestAwareAuthenticationSuccessHandler();
    }


    @Bean
    public AuthorizationServerSettings getAuthorizationServerSettings(){
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:9000/auth")
                .build();
    }

    @Bean
    public JWKSource<SecurityContext> getJwkSource() {
        /*
            JWK (JSON Web Key) is a format to represent cryptographic keys used for signing JWTs.
            It’s a JSON-based structure that contains the key type, algorithm, and public/private key info.
            Spring Authorization Server supports JWK for signing and verifying JWTs
         */

        return (jwkSelector, securityContext) ->{
            List<RsaKeyPairDto> rsaKeyPairDtoList = rsaKeyPairService.getAllRsaKeyPairs();
            List<JWK> jwkList = new ArrayList<>(rsaKeyPairDtoList.size());
            for(RsaKeyPairDto rsaKeyPairDto : rsaKeyPairDtoList){
                RSAKey rsaKey =  new RSAKey
                        .Builder(rsaKeyPairDto.getPublicKey()).privateKey(rsaKeyPairDto.getPrivateKey()).keyID(rsaKeyPairDto.getId())
                        .build();
                if(jwkSelector.getMatcher().matches(rsaKey)){
                    jwkList.add(rsaKey);
                }
            }
            return jwkList;
        };
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> getOAuth2TokenCustomizer() {
        return (context) -> {
            Authentication principal = context.getPrincipal();
            if(OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())){
                Set<String> authorities = principal.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
                context.getClaims().claim("authorities", authorities);
            }
            if(OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())){
                Set<String> authorities = principal.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
                context.getClaims().claim("authorities", authorities);
                context.getClaims().claim("details", "Spring boot  Tutorial");
            }
            //We get the last RsaKey and pass the kid to the keyId of the Token
            List<RsaKeyPairDto> keyPairs = this.rsaKeyPairService.getAllRsaKeyPairs();
            String kid = keyPairs.get(0).getId();
            context.getJwsHeader().keyId(kid);
        };
    }

    @Bean
    public NimbusJwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        /*
            The rotation happens because everytime we use the JwtEncoder impl (NimbusJwtEncoder) to encode we are getting the jwts.get(0) obj
            from the list of JWKs (Json Web Keys) which are the private, public keys used to sign a token
         */
        return new NimbusJwtEncoder(jwkSource);
    }
    @Bean
    public OAuth2TokenGenerator<OAuth2Token> delegatingOAuth2TokenGenerator(JwtEncoder encoder, OAuth2TokenCustomizer<JwtEncodingContext> customizer){
        JwtGenerator jwtTokenGenerator = new JwtGenerator(encoder);
        jwtTokenGenerator.setJwtCustomizer(customizer);
        return new DelegatingOAuth2TokenGenerator(
                jwtTokenGenerator,                     // Tries to generate a JWT token first
                new OAuth2AccessTokenGenerator(),  // If JWT fails, tries an opaque access token
                new OAuth2RefreshTokenGenerator()  // If access token isn't requested, tries refresh token
        );
    }



}
