package com.emerson.identity.identity_service.security;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Collection;

public class MFAAuthenticationToken extends AnonymousAuthenticationToken {

    private Authentication initialAuthenticationResult;

    public MFAAuthenticationToken(Authentication initialAuthenticationResult, String authority){
        super("ANNONYMOUS", "ANNONYMOUS_USER", AuthorityUtils.createAuthorityList(authority));
        this.initialAuthenticationResult = initialAuthenticationResult;
    }
    public Authentication getInitialAuthenticationResult(){
        return this.initialAuthenticationResult;
    }

}
