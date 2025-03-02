package com.emerson.identity.identity_service.entities.oauth2;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.util.Objects;

@Entity
@Table (name = "authorizationConsent")
@IdClass (AuthorizationConsent.AuthorizationConsentId.class)
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class AuthorizationConsent {
    @EmbeddedId
    private AuthorizationConsentId authorizationConsentId;
    @Column (length = 1000)
    private String authorities;

    public static class AuthorizationConsentId implements Serializable {
        private static final long serialVersionUID = 1L;
        private String registeredClientId;
        private String principalName;

        public String getRegisteredClientId() {
            return registeredClientId;
        }

        public void setRegisteredClientId(String registeredClientId) {
            this.registeredClientId = registeredClientId;
        }

        public String getPrincipalName() {
            return principalName;
        }

        public void setPrincipalName(String principalName) {
            this.principalName = principalName;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            AuthorizationConsentId that = (AuthorizationConsentId) o;
            return registeredClientId.equals(that.registeredClientId) && principalName.equals(that.principalName);
        }

        @Override
        public int hashCode() {
            return Objects.hash(registeredClientId, principalName);
        }
    }
}
