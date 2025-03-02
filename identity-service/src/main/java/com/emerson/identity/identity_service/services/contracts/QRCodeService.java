package com.emerson.identity.identity_service.services.contracts;

public interface QRCodeService {
    boolean checkCode(String code, String userSecret);
    String generateSecret();
    String generateQrCodeImg(String userKey, String base32Secret);
    String generateCodeFromSecret(String base32Secret );
}
