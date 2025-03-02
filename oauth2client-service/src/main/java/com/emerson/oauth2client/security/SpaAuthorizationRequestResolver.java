package com.emerson.oauth2client.security;

import com.emerson.oauth2client.config.CustomProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.stream.Collectors;


@Slf4j
public class SpaAuthorizationRequestResolver implements ServerOAuth2AuthorizationRequestResolver {

    private ServerWebExchangeMatcher exchangeMatcher;
    private ReactiveClientRegistrationRepository clientRegistrationRepository;
    private Map<String, CompositeOAuth2AuthorizationRequestCustomizer> requestCustomizerMap;
    private final URI clientUri;

    public SpaAuthorizationRequestResolver(ReactiveClientRegistrationRepository repo, CustomProperties customProperties, OAuth2ClientProperties oAuth2ClientProperties){
        this.clientRegistrationRepository = repo;
        this.exchangeMatcher = new PathPatternParserServerWebExchangeMatcher("/oauth2/authorization/{registrationId}");
        this.requestCustomizerMap = createAuthorizationRequestCustomizers(customProperties, oAuth2ClientProperties);
        this.clientUri = customProperties.getClientUri();
    }

    @Override
    public Mono<OAuth2AuthorizationRequest> resolve(ServerWebExchange exchange){
        return exchangeMatcher.matches(exchange)
                .filter(matchResult -> matchResult.isMatch())
                .map(matchResult -> matchResult.getVariables())
                .map(variables -> variables.get("registrationId"))
                .cast(String.class)
                .flatMap(clientRegistrationId -> resolve(exchange, clientRegistrationId));
    }

    @Override
    public Mono<OAuth2AuthorizationRequest> resolve(ServerWebExchange exchange, String clientRegistrationId){
        var composite = requestCustomizerMap.get(clientRegistrationId);
        if(composite == null) return null;
        final var delegate = new DefaultServerOAuth2AuthorizationRequestResolver(clientRegistrationRepository);
        delegate.setAuthorizationRequestCustomizer(composite);
        return savePostLoginUri(exchange)
                .then(delegate.resolve(exchange, clientRegistrationId))
                .map(this::postProcess);
    }

    public Mono<WebSession> savePostLoginUri(ServerWebExchange exchange){
        final var request = exchange.getRequest();
        final var headers = request.getHeaders();
        final var params = request.getQueryParams();

        return exchange.getSession().map(session -> {
            Optional.ofNullable(
                    Optional.ofNullable(params.getFirst("post_login_success_uri"))
                            .orElse(Optional.ofNullable(headers.getFirst("X-POST-LOGIN-SUCCESS-URI"))
                                    .orElse(null))
            ).filter(StringUtils::hasText).map(URI::create).ifPresent(uri -> session.getAttributes().put("post_login_success_uri", uri) );

            Optional.ofNullable(
                    Optional.ofNullable(
                            headers.getFirst("X-POST-LOGIN-FAILURE-URI")
                    ).orElse(
                            Optional.ofNullable(
                                    params.getFirst("post_login_failure_uri")
                            ).orElse(null)
                    )
            ).filter(StringUtils::hasText).map(URI::create).ifPresent(uri -> session.getAttributes().put("post_login_failure_uri", uri));
            return session;
        });
    }

    private Map<String, CompositeOAuth2AuthorizationRequestCustomizer> createAuthorizationRequestCustomizers(CustomProperties customProperties, OAuth2ClientProperties oAuth2ClientProperties){
        return oAuth2ClientProperties
                .getRegistration()
                .entrySet()
                .stream()
                .collect(Collectors
                        .toMap(entrySet1 -> entrySet1.getKey(), entrySet2 -> {
                            var composite = new CompositeOAuth2AuthorizationRequestCustomizer();
                            Map<String, List<String>> injectedParamsFromYml = customProperties.getExtraAuthorizationRequestParams(entrySet2.getKey());
                            if(injectedParamsFromYml.size() > 0)  composite.addCustomizer(addAdditionalParamsToRequestCustomizer(injectedParamsFromYml));
                            if(customProperties.isPkceForced()) composite.addCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
                            return composite;
                        })
                );
    }

    private Consumer<OAuth2AuthorizationRequest.Builder> addAdditionalParamsToRequestCustomizer(Map<String, List<String>> param){
        return (builder) -> {
            param.forEach((key, value) -> {
                builder.additionalParameters(map -> map.put(key, String.join(",", value)));
            });
        };
    }

    private OAuth2AuthorizationRequest postProcess(OAuth2AuthorizationRequest request) {
        final var modified = OAuth2AuthorizationRequest.from(request);

        final var original = URI.create(request.getRedirectUri());
        final var redirectUri =
                UriComponentsBuilder
                        .fromUri(clientUri)
                        .path(original.getPath())
                        .query(original.getQuery())
                        .fragment(original.getFragment())
                        .build()
                        .toString();
        modified.redirectUri(redirectUri);
        log.info("Changed OAuth2AuthorizationRequest redirectUri from {} to {}", original, redirectUri);
        return modified.build();
    }
}
