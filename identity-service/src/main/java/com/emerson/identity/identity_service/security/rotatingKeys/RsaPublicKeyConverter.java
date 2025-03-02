package com.emerson.identity.identity_service.security.rotatingKeys;

import org.springframework.core.serializer.Deserializer;
import org.springframework.core.serializer.Serializer;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.stereotype.Component;
import org.springframework.util.FileCopyUtils;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Component
public class RsaPublicKeyConverter implements Serializer<RSAPublicKey>, Deserializer<RSAPublicKey> {

    private final TextEncryptor textEncryptor;
    private final String BEGIN_HEADER = "-----BEGIN PRIVATE KEY-----\n";
    private final String END_HEADER = "\n-----END PRIVATE KEY-----";

    public RsaPublicKeyConverter (TextEncryptor textEncryptor) {
        this.textEncryptor = textEncryptor;
    }
    @Override
    public RSAPublicKey deserialize(InputStream inputStream) throws IOException{
        try{
            String pem = this.textEncryptor.decrypt(FileCopyUtils.copyToString(new InputStreamReader(inputStream)));
            String publicKeyPem = pem.replace(BEGIN_HEADER, "").replace(END_HEADER, "");

            byte[] encoded = Base64.getMimeDecoder().decode(publicKeyPem);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);

        } catch (Throwable e) {
            throw new IllegalArgumentException("there's been an exception", e);
        }
    }

    @Override
    public void serialize(RSAPublicKey key, OutputStream outputStream) throws IOException{
        X509EncodedKeySpec x509EncodedKeySpec  = new X509EncodedKeySpec(key.getEncoded());
        String pem = BEGIN_HEADER + Base64.getMimeEncoder().encodeToString(x509EncodedKeySpec.getEncoded()) + END_HEADER;
        outputStream.write(this.textEncryptor.encrypt(pem).getBytes());
    }
}
