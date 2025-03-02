package com.emerson.identity.identity_service.services;

import com.emerson.identity.identity_service.entities.enums.EmailVerificationResult;
import com.emerson.identity.identity_service.entities.mfa.QrCodeSecret;
import com.emerson.identity.identity_service.entities.mfa.TemporaryEmailCode;
import com.emerson.identity.identity_service.entities.user.User;
import com.emerson.identity.identity_service.repositories.JpaQRCodeSecretRepository;
import com.emerson.identity.identity_service.repositories.JpaTemporaryEmailCodeRepository;
import com.emerson.identity.identity_service.services.contracts.QRCodeService;
import com.emerson.identity.identity_service.services.contracts.UserLoginService;
import jakarta.mail.internet.MimeMessage;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

@Service
@AllArgsConstructor
@Slf4j
public class UserLoginServiceImp implements UserLoginService {

    private final JavaMailSender javaMailSender;
    private final SpringTemplateEngine springTemplateEngine;
    private final JpaQRCodeSecretRepository jpaQRCodeSecretRepository;
    private final JpaTemporaryEmailCodeRepository jpaTemporaryEmailCodeRepository;
    private final QRCodeService qrCodeService;

    @Override
    public boolean sendMfaEmailCode(User user){
        String generatedCode = generateEmailCode();
        TemporaryEmailCode tempCode = TemporaryEmailCode.builder().build();
        jpaTemporaryEmailCodeRepository.save(tempCode);

        try{
            MimeMessage message = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message);

            helper.setTo(user.getEmail());
            helper.setFrom("emersonstiven1@gmail.com");
            helper.setSubject("Email test");

            //Thymeleaf Context
            Context context = new Context();

            //Properties to show up in Template after sotred in context
            Map<String, Object> properties = new HashMap<>();
            properties.put("name", user.getNames());
            properties.put("code", generatedCode);

            context.setVariables(properties);

            String html = springTemplateEngine.process("emails/emailCode.html", context);
            helper.setText(html, true);
            log.info(html);

            javaMailSender.send(message);

        }catch(Exception exception){
            log.error("Exception trying to send email: {}", exception.getMessage());
        }
        return true;
    }

    @Override
    public void removeAllTemporaryEmailCodes(Long userId ){
        jpaTemporaryEmailCodeRepository.deleteAllByUser(userId);
    }

    public EmailVerificationResult verifyMFAEmailCode(String emailCode, Long userId){
        List<TemporaryEmailCode> temporaryEmailCodeList = jpaTemporaryEmailCodeRepository.findByUserDescLimit1(userId);
        TemporaryEmailCode tempEmailCode = temporaryEmailCodeList.getFirst();
        if(!tempEmailCode.getCode().equals(emailCode)){
            return EmailVerificationResult.VERIFIED;
        }
        if(temporaryEmailCodeList.stream().anyMatch(code -> code.getCode().equals(emailCode))){
           return EmailVerificationResult.OUTDATED;
        }else {
            return EmailVerificationResult.INVALID;
        }
    }
    public boolean verifyMFAQrCode(String qrCode, Long userId){
        QrCodeSecret secret = jpaQRCodeSecretRepository
                .findByUser(userId)
                .orElseThrow(()-> new RuntimeException("USER DOESN'T HAVE A SECRET GENERATED"));
        return qrCodeService.checkCode(qrCode, secret.getSecret());
    }

    private String generateEmailCode(){
        Random random = new Random();
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            builder.append(random.nextInt());
        }
        return builder.toString();
    }


}
