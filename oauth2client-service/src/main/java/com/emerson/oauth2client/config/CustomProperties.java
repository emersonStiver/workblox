package com.emerson.oauth2client.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@ConfigurationProperties(prefix = "com.emerson.oauth2client.config")
@Data
@Component
public class CustomProperties {
    private URI clientUri;

    private boolean isPkceForced;

    private Optional<URI> postLoginRedirectUri;

    private List<CorsProperties> cors = List.of();

    private HttpStatus postAuthorizationCodeStatus;

    private List<String> securityMatchers = List.of();
    private List<String> permitAll = List.of();

    private BackChannelLogoutProperties backChannelLogoutProperties = new BackChannelLogoutProperties();

    private Map<String,
                    Map<String, List<String>>
            > extraAuthorizationRequestParams = new HashMap<>();

    public MultiValueMap<String, String> getExtraAuthorizationRequestParams(String registrationId){
        return Optional
                .ofNullable(this.extraAuthorizationRequestParams.get(registrationId))
                .map(LinkedMultiValueMap::new)
                .orElse(new LinkedMultiValueMap<>());
    }

    @Data
    @ConfigurationProperties
    public static class BackChannelLogoutProperties{
        private boolean enabled = false;
        private Optional<String> internalLogoutUri = Optional.empty();
    }

    @Data
    public class CorsProperties {
        private String path = "/**";
        private Boolean allowCredentials = null;
        private List<String> allowedOriginPatterns = List.of("*");
        private List<String> allowedHeaders = List.of("*");
        private List<String> exposedHeaders = List.of("*");
        private List<String> allowedMethods = List.of("*");
        private Long maxAge = null;
        private Boolean disableAnonymousOptions = false;

    }


}
