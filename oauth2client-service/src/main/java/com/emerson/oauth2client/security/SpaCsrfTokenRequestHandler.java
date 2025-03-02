package com.emerson.oauth2client.security;

import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.server.csrf.XorServerCsrfTokenRequestAttributeHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Optional;
@Component
final class SpaCsrfTokenRequestHandler extends ServerCsrfTokenRequestAttributeHandler {
    private final ServerCsrfTokenRequestAttributeHandler delegate = new XorServerCsrfTokenRequestAttributeHandler();

    @Override
    public void handle(ServerWebExchange exchange, Mono<CsrfToken> csrfToken){
        /*
         * Always use XorCsrfTokenRequestAttributeHandler to provide BREACH protection of the CsrfToken when it is rendered in the response body.
         */
        this.delegate.handle(exchange, csrfToken);
    }

    @Override
    public Mono<String> resolveCsrfTokenValue(ServerWebExchange exchange, CsrfToken csrfToken){
        /*
         * If the request contains a request header, use CsrfTokenRequestAttributeHandler to resolve the CsrfToken. This applies when a single-page
         * application includes the header value automatically, which was obtained via a cookie containing the raw CsrfToken.
         *
         * In all other cases (e.g. if the request contains a request parameter), use XorCsrfTokenRequestAttributeHandler to resolve the CsrfToken.
         * This applies when a server-side rendered form includes the _csrf request parameter as a hidden input.
         */
        // @formatter:off
        final boolean hasHeader = Optional.ofNullable(exchange.getRequest().getHeaders().get(csrfToken.getHeaderName()))
                .orElse(List.of())
                .stream()
                .filter(StringUtils::hasText)
                .count() > 0;
        // @formatter:on
        return hasHeader ? super.resolveCsrfTokenValue(exchange, csrfToken) : this.delegate.resolveCsrfTokenValue(exchange, csrfToken);
    }
}