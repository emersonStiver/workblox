package com.emerson.oauth2client.security;

import com.emerson.oauth2client.config.CustomProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Collection;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
public class SpaRedirectStrategy implements ServerRedirectStrategy {
    HttpStatus defaultStatus;
    private final CustomProperties properties;

    @Override
    public Mono<Void> sendRedirect(ServerWebExchange exchange, URI location){
        return Mono.fromRunnable(()-> {
            HttpStatus statusCode = Optional.ofNullable(exchange.getRequest().getHeaders().get("X-RESPONSE-STATUS"))
                    .stream()
                    .flatMap(Collection::stream)
                    .filter(StringUtils::hasLength)
                    .findAny()
                    .map(status -> {
                        try{
                            return HttpStatus.valueOf(Integer.parseInt(status));
                        }catch(IllegalArgumentException e){
                            return HttpStatus.valueOf(status.toUpperCase());
                        }
                    }).orElse(properties.getPostAuthorizationCodeStatus());
            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(statusCode);
            response.getHeaders().setLocation(location);
        });
    }
}
