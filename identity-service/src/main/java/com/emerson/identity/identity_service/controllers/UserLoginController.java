package com.emerson.identity.identity_service.controllers;

import com.emerson.identity.identity_service.configs.CustomAuthorizationServerProperties;
import com.emerson.identity.identity_service.controllers.dtos.MfaCodeSentDto;
import com.emerson.identity.identity_service.controllers.validators.CompositeValidator;
import com.emerson.identity.identity_service.entities.enums.EmailVerificationResult;
import com.emerson.identity.identity_service.entities.enums.MFAMethod;
import com.emerson.identity.identity_service.entities.user.User;
import com.emerson.identity.identity_service.security.MFAAuthenticationSuccessHandler;
import com.emerson.identity.identity_service.security.MFAAuthenticationToken;
import com.emerson.identity.identity_service.security.UserSecurityDetails;
import com.emerson.identity.identity_service.services.contracts.UserLoginService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.ui.Model;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping(value = "/login")
@AllArgsConstructor
public class UserLoginController {

    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();
    private final UserLoginService userLoginService;
    private final CompositeValidator compositeValidator;
    private final MFAAuthenticationSuccessHandler securityQuestionSuccessHandler = new MFAAuthenticationSuccessHandler("/security-question", "MFA_AUTHENTICATION_CLEARED");
    private final AuthenticationSuccessHandler successHandler;
    private final AuthenticationFailureHandler authenticatorFailureHandler =
            new SimpleUrlAuthenticationFailureHandler("/authenticator?error");


    @InitBinder
    public void loadValidators(WebDataBinder webDataBinder){
        webDataBinder.addValidators(compositeValidator);
    }

    @GetMapping(value = "/login")
    public String loginPage(){
        return "login";
    }

    @GetMapping(value = "/security-question")
    public String getSecurityQuestionPage(Model model){
        return "security-question";
    }

    @GetMapping(value = "/mfa/twoFactorAuthentication")
    public String getTwoFactorAuthenticationPage(@CurrentSecurityContext SecurityContext context, Model model, CustomAuthorizationServerProperties properties){

        //contain the options available to complete the MFA (email, authenticator, sms, accepting the request from the mobile app)
        User user = getAuthenticatedUser(context);

        //Filter only the MFA methods the user has enabled
        Map<MFAMethod, String> userMfaEndpoints  = properties.getMfaEndpoints()
                .entrySet()
                .stream()
                .filter(entry -> user.getMfaMethods().stream().anyMatch(userMfaMethod -> userMfaMethod.getMethodName().equals(entry
                        .getKey().getMethodName()))
                ).collect(Collectors.toMap(entry1 -> entry1.getKey(), entry2 ->entry2.getValue() ));

        userMfaEndpoints.forEach((method, url) -> model.addAttribute(method.getMethodName(), url));

        return "twoFactorAuthentication";
    }

    // ------------------------ Email two-factor authentication ------------------------

    @PostMapping
    public void addTwoFactorAuthenticationMethod(){

    }

    @PostMapping("/mfa/sendEmailCode")
    public ResponseEntity<?> sendEmailVerificationCode(@CurrentSecurityContext SecurityContext securityContext){
        User user =  getAuthenticatedUser(securityContext);
        if(!userLoginService.sendMfaEmailCode(user)){
            return ResponseEntity.badRequest().body("Unable to send code to the email " + user.getEmail());
        }
        return ResponseEntity.ok("Email sent successfully");

    }

    @PostMapping("/mfa/verifyEmailCode")
    public void sendEmailVerificationCode(
            @RequestBody MfaCodeSentDto mfaCodeSentDto,
            @CurrentSecurityContext SecurityContext context,
            HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {

        User user =  getAuthenticatedUser(context);

        EmailVerificationResult result = userLoginService.verifyMFAEmailCode(mfaCodeSentDto.getCode(), user.getUserId());

        // Handle invalid or outdated code
        if (result == EmailVerificationResult.INVALID) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid verification code.");
            return;
        } else if (result == EmailVerificationResult.OUTDATED) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Verification code has expired.");
            return;
        }
        userLoginService.removeAllTemporaryEmailCodes(user.getUserId());


        // Proceed with authentication success based on security question status
        if (!user.isSecurityQuestionEnabled()) {
            successHandler.onAuthenticationSuccess(request, response, getInitialAuthenticationTokenResult(request, response));
        } else {
            securityQuestionSuccessHandler.onAuthenticationSuccess(request, response, getInitialAuthenticationTokenResult(request, response));
        }
    }



    // ------------------------ QR Code two-factor authentication ------------------------

    @PostMapping("/mfa/verifyAuthenticatorCode")
    public void authenticatorVerification(@RequestBody MfaCodeSentDto mfaCodeSentDto, @CurrentSecurityContext SecurityContext context, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException{

        User user = getAuthenticatedUser(context);

        boolean result = userLoginService.verifyMFAQrCode(mfaCodeSentDto.getCode(), user.getUserId());
        if(!result){
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid authenticator code"); //sends response msg
            // this.authenticatorFailureHandler.onAuthenticationFailure(request, response, new BadCredentialsException("Bad credentials")); //triggers a redirect
            return;
        }
        //Proceed with authentication success based on security question status
        if(!user.isSecurityQuestionEnabled()){
            successHandler.onAuthenticationSuccess(request, response, getInitialAuthenticationTokenResult(request, response));
        }
        securityQuestionSuccessHandler.onAuthenticationSuccess(request, response, getInitialAuthenticationTokenResult(request, response));

    }

    private Authentication getInitialAuthenticationTokenResult(HttpServletRequest request, HttpServletResponse response){
        SecurityContext securityContext = SecurityContextHolder.getContext();
        MFAAuthenticationToken auth = (MFAAuthenticationToken) securityContext.getAuthentication();

        SecurityContext newSecurityContext = SecurityContextHolder.createEmptyContext();
        Authentication primaryAuthToken = auth.getInitialAuthenticationResult();
        newSecurityContext.setAuthentication(primaryAuthToken);
        SecurityContextHolder.setContext(newSecurityContext);
        securityContextRepository.saveContext(newSecurityContext, request, response);
        return primaryAuthToken;
    }

    private User getAuthenticatedUser(SecurityContext context){
        MFAAuthenticationToken mfaToken = (MFAAuthenticationToken) context.getAuthentication();
        UsernamePasswordAuthenticationToken authToken = (UsernamePasswordAuthenticationToken) mfaToken.getInitialAuthenticationResult();
        UserSecurityDetails userSecurityDetails = (UserSecurityDetails) authToken.getPrincipal();
        return userSecurityDetails.getUser();
    }
}
