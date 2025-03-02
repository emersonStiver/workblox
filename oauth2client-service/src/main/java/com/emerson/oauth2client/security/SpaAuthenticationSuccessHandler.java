package com.emerson.oauth2client.security;

import com.emerson.oauth2client.config.CustomProperties;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import reactor.core.publisher.Mono;

import java.net.URI;

public class SpaAuthenticationSuccessHandler implements ServerAuthenticationSuccessHandler {
    private URI defaultUri;
    private SpaRedirectStrategy spaRedirectStrategy;
    private CustomProperties properties;
    public SpaAuthenticationSuccessHandler(){
        this.defaultUri = properties.getPostLoginRedirectUri().orElse(URI.create("/"));
    }
    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication){
        return webFilterExchange.getExchange().getSession().flatMap(session -> {
            URI redirectUri = session.getAttributeOrDefault("post_login_success_uri", defaultUri);
            return spaRedirectStrategy.sendRedirect(webFilterExchange.getExchange(), redirectUri);
        });
    }
}
