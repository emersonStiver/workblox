package com.emerson.identity.identity_service.security.rotatingKeys;

import lombok.RequiredArgsConstructor;
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
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

@Component
@RequiredArgsConstructor
public class RsaPrivateKeyConverter implements Serializer<RSAPrivateKey>, Deserializer<RSAPrivateKey> {

    private final TextEncryptor encryptor;
    private final String BEGIN_HEADER = "-----BEGIN PRIVATE KEY-----\n";
    private final String END_HEADER = "\n-----END PRIVATE KEY-----";

    @Override
    public RSAPrivateKey deserialize(InputStream inputStream) throws IOException{
        try{
            //This is a bridge between byte streams to character streams, we have gotten the source of bytes and decoded them into the character representation
            InputStreamReader reader = new InputStreamReader(inputStream);

            //We now read the "reader" to build a String
            String pem = this.encryptor.decrypt(FileCopyUtils.copyToString(reader));

            //We cut the header and footer of the rsa key
            String privateKeyPem = pem.replace(BEGIN_HEADER, "").replace(END_HEADER, "");

            byte[] encoded = Base64.getMimeDecoder().decode(privateKeyPem); //We convert the String into a new byte array

            //We use the byte array to build a KeySpec which is then used to build the PrivateKey
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);

        }catch (Throwable throwable){
            throw new IllegalArgumentException("there's been an exception", throwable);
        }
    }

    @Override
    public void serialize(RSAPrivateKey object, OutputStream outputStream) throws IOException{
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(object.getEncoded());
        String pem = BEGIN_HEADER +  Base64.getMimeEncoder().encodeToString(pkcs8EncodedKeySpec.getEncoded()) + END_HEADER;
        outputStream.write(this.encryptor.encrypt(pem).getBytes());
    }
}
