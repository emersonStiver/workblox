package com.emerson.identity.identity_service.security;

import com.emerson.identity.identity_service.entities.user.User;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

import java.io.IOException;

public class MFAAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private SecurityContextRepository securityContextRepository;
    private AuthenticationSuccessHandler mfaNotEnabled = new SavedRequestAwareAuthenticationSuccessHandler();
    private AuthenticationSuccessHandler successHandler;
    private String authority;

    public MFAAuthenticationSuccessHandler(String successUrl, String gainedAuthority){
        SimpleUrlAuthenticationSuccessHandler handler = new SimpleUrlAuthenticationSuccessHandler(successUrl);
        handler.setAlwaysUseDefaultTargetUrl(true);
        successHandler = handler;
        this.authority = gainedAuthority;
    }
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException{
        if(authentication instanceof UsernamePasswordAuthenticationToken){
            User user = (User) authentication.getPrincipal();
            if(!user.isMultiFactorAuthenticationEnabled()){
                mfaNotEnabled.onAuthenticationSuccess(request, response, authentication);
            }
            persistRequest(request, response, new MFAAuthenticationToken(authentication, this.authority));
            this.successHandler.onAuthenticationSuccess(request, response, authentication);
        }
    }

    private void persistRequest(HttpServletRequest request, HttpServletResponse response, MFAAuthenticationToken mfaAuthenticationToken){
        /*
            We store the MFAAuthenticationToken in the session, so when the user sends the /twoFactorAuthentication POST request
            with the email or authentication code attached to it, we will be able to retrieve the Authentication token stored
            initially during the credentials verification

            This token includes the principal which may have attributes like isSecurityQuestionEnabled that may allow us to decide if
            more steps must be taken before storing the UsernamePasswordAuthentication token in the session and redirect the user
            to the endpoint needed
        */
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(mfaAuthenticationToken);
        SecurityContextHolder.setContext(context);
        securityContextRepository.saveContext(context, request, response);
    }
}
