package com.emerson.oauth2client.security;

import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest.Builder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Stream;

public class CompositeOAuth2AuthorizationRequestCustomizer implements Consumer<OAuth2AuthorizationRequest.Builder> {

    private final List<Consumer<OAuth2AuthorizationRequest.Builder>> delegates;
    public CompositeOAuth2AuthorizationRequestCustomizer(Consumer<OAuth2AuthorizationRequest.Builder>... customizers){
        delegates = new ArrayList<>(customizers.length + 3);
        Collections.addAll(delegates, customizers);
    }
    public CompositeOAuth2AuthorizationRequestCustomizer(
            CompositeOAuth2AuthorizationRequestCustomizer other,
            Consumer<OAuth2AuthorizationRequest.Builder> ... customizers
    ){
        this(Stream.concat(other.delegates.stream(), Stream.of(customizers)).toArray(Consumer[]::new));
    }
    @Override
    public void accept(Builder builder){
        for(var consumer : delegates){
            consumer.accept(builder);
        }
    }

    public CompositeOAuth2AuthorizationRequestCustomizer addCustomizer(Consumer<OAuth2AuthorizationRequest.Builder> customizer){
        this.delegates.add(customizer);
        return this;
    }
}
