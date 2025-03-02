package com.emerson.oauth2client.config;

import com.emerson.oauth2client.security.SpaAuthenticationFailureHandler;
import com.emerson.oauth2client.security.SpaAuthenticationSuccessHandler;
import com.emerson.oauth2client.security.SpaRedirectStrategy;
import io.r2dbc.spi.ConnectionFactories;
import io.r2dbc.spi.ConnectionFactory;
import io.r2dbc.spi.ConnectionFactoryOptions;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.R2dbcReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.logout.DelegatingServerLogoutHandler;
import org.springframework.security.web.server.authentication.logout.SecurityContextServerLogoutHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.authentication.logout.WebSessionServerLogoutHandler;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.server.util.matcher.OrServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.stream.Collectors;

import static io.r2dbc.spi.ConnectionFactoryOptions.*;
import static io.r2dbc.spi.ConnectionFactoryOptions.DATABASE;

@Slf4j
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain getSecurityWebFilterChain(
            ServerHttpSecurity filterChain,
            CustomProperties properties,
            ServerAuthenticationSuccessHandler successHandler,
            ServerAuthenticationFailureHandler failureHandler,
            ServerRedirectStrategy redirectStrategy,
            ReactiveOAuth2AuthorizedClientService auth2AuthorizedClientService,
            ReactiveClientRegistrationRepository registrationRepository,
            ServerOAuth2AuthorizationRequestResolver resolver,
            ServerCsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler,
            ServerLogoutSuccessHandler serverLogoutSuccessHandler) {

        filterChain
                .securityMatcher(
                        new OrServerWebExchangeMatcher(
                                properties.getSecurityMatchers()
                                        .stream()
                                        .map(PathPatternParserServerWebExchangeMatcher::new)
                                        .collect(Collectors.toUnmodifiableList()))
                );

        filterChain.authorizeExchange(authorizeRoutes -> {
            authorizeRoutes.pathMatchers(properties.getPermitAll().toArray(new String[]{}));
            authorizeRoutes.anyExchange().authenticated();
        });

        filterChain.logout(logoutSpec -> {
            logoutSpec.logoutHandler(new DelegatingServerLogoutHandler(new SecurityContextServerLogoutHandler(), new WebSessionServerLogoutHandler()));
            logoutSpec.logoutSuccessHandler(serverLogoutSuccessHandler);
            /*
                Once the logout process is completed on the client app, we initiate the RP logout, that's because:
                When a user logs in via OIDC, an authentication session is established not only on your application
                (the client or relying party) but also at the IDP. Redirecting the user to the IDP ensures that
                the session on the IDP is also terminated. If you only cleared the client-side session, the user might
                still be considered logged in at the IDP, which could lead to automatic re-authentication if they try
                to log in again.
             */
        });

        if(properties.getBackChannelLogoutProperties().isEnabled()){
            filterChain.oidcLogout(oidcLogoutSpec -> {
               oidcLogoutSpec.backChannel( configurer -> properties.getBackChannelLogoutProperties().getInternalLogoutUri().ifPresent(configurer::logoutUri));
            });
            // Back-channel logout is used for the IDP to notify the client directly (via a server-to-server call) to terminate the session
            // PENDING: CREATE A CUSTOM IMPLEMENTATION OF ReactiveOidcSessionRegistry
        }

        filterChain.oauth2Login(oAuth2LoginSpec -> {
            oAuth2LoginSpec.securityContextRepository(new WebSessionServerSecurityContextRepository());
            oAuth2LoginSpec.authenticationSuccessHandler(successHandler);
            oAuth2LoginSpec.authenticationFailureHandler(failureHandler);
            oAuth2LoginSpec.authorizationRedirectStrategy(redirectStrategy);
            oAuth2LoginSpec.authorizationRequestResolver(resolver);
            oAuth2LoginSpec.authorizedClientService(auth2AuthorizedClientService);
            oAuth2LoginSpec.clientRegistrationRepository(registrationRepository);
        });

        filterChain.cors(corsSpec -> {
            if(properties.getCors().size() > 0){
                corsSpec.disable();
            }else{
                final var source = new UrlBasedCorsConfigurationSource();
                for(CustomProperties.CorsProperties c : properties.getCors()){
                    final var configuration = new CorsConfiguration();
                    configuration.setAllowCredentials(c.getAllowCredentials());
                    configuration.setAllowedHeaders(c.getAllowedHeaders());
                    configuration.setAllowedMethods(c.getAllowedMethods());
                    configuration.setAllowedOriginPatterns(c.getAllowedOriginPatterns());
                    configuration.setExposedHeaders(c.getExposedHeaders());
                    configuration.setMaxAge(c.getMaxAge());
                    source.registerCorsConfiguration(c.getPath(),configuration);
                }
                corsSpec.configurationSource(source);
            }
        });

        filterChain.csrf(csrfSpec -> {
            csrfSpec.csrfTokenRequestHandler(csrfTokenRequestAttributeHandler);
            csrfSpec.csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse());
        });

        filterChain.securityContextRepository(new WebSessionServerSecurityContextRepository());

        return filterChain.build();
    }

    @Bean
    public ServerLogoutSuccessHandler getServerLogoutSuccessHandler(ReactiveClientRegistrationRepository clientRegistrationRepository, CustomProperties properties){
        var clientInitiatedLogoutSuccessHandler = new OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository);
        clientInitiatedLogoutSuccessHandler.setPostLogoutRedirectUri(properties.getPostLoginRedirectUri().map(URI::getPath).orElse("/"));
        return clientInitiatedLogoutSuccessHandler;
    }

    @Bean
    public ReactiveOAuth2AuthorizedClientService getReactiveOAuth2AuthorizedClientService(DatabaseClient databaseClient, ReactiveClientRegistrationRepository clientRegistrationRepository){
        return new R2dbcReactiveOAuth2AuthorizedClientService(databaseClient, clientRegistrationRepository);
    }
    @Bean
    public ServerAuthenticationFailureHandler getServerAuthenticationFailureHandler(){
        return new SpaAuthenticationFailureHandler();
    }
    @Bean
    public ServerAuthenticationSuccessHandler getServerAuthenticationSuccessHandler(){
        return new SpaAuthenticationSuccessHandler();
    }
    @Bean
    public ServerRedirectStrategy getServerRedirectStrategy(CustomProperties properties){
        return new SpaRedirectStrategy(properties);
    }
    @Bean
    public DatabaseClient getDatabaseClient(ConnectionFactory connectionFactory){
        return DatabaseClient.create(connectionFactory);
    }
    @Bean
    public ConnectionFactory getConnectionFactory(){
        return ConnectionFactories.get(ConnectionFactoryOptions.builder()
                .option(DRIVER, "postgresql")
                .option(HOST, "localhost")
                .option(PORT, 5432)
                .option(USER, "postgres")
                .option(PASSWORD, "Germany1#")
                .option(DATABASE, "postgres")
                .build());
    }
    @Bean
    WebFilter csrfCookieWebFilter() {
        return (exchange, chain) -> {
            exchange.getAttributeOrDefault(CsrfToken.class.getName(), Mono.empty()).subscribe();
            return chain.filter(exchange);
        };
    }


}
