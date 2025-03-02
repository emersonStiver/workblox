package com.emerson.identity.identity_service.configs;

import com.emerson.identity.identity_service.entities.enums.MFAMethod;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.Map;

@Data
@ConfigurationProperties(prefix = "com.emerson.authserver.config")
@Component
public class CustomAuthorizationServerProperties {

    private Map<MFAMethod, String> mfaEndpoints = Map.of();
}
