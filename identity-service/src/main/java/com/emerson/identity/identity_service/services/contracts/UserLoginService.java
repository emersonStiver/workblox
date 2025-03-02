package com.emerson.identity.identity_service.services.contracts;

import com.emerson.identity.identity_service.entities.enums.EmailVerificationResult;
import com.emerson.identity.identity_service.entities.user.User;

public interface UserLoginService {
    boolean sendMfaEmailCode(User user);
    void removeAllTemporaryEmailCodes(Long userId);
    EmailVerificationResult verifyMFAEmailCode(String emailCode, Long user);
    boolean verifyMFAQrCode(String qrCode, Long user);
}
