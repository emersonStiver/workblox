package com.emerson.identity.identity_service.services;

import com.emerson.identity.identity_service.controllers.dtos.RsaKeyPairDto;
import com.emerson.identity.identity_service.entities.signingKeys.RsaKeyPair;
import com.emerson.identity.identity_service.repositories.JpaRsaKeyRepository;
import com.emerson.identity.identity_service.security.rotatingKeys.RsaPrivateKeyConverter;
import com.emerson.identity.identity_service.security.rotatingKeys.RsaPublicKeyConverter;
import com.emerson.identity.identity_service.services.contracts.RsaKeyPairService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class RsaKeyPairServiceImp implements RsaKeyPairService {

    private final JpaRsaKeyRepository jpaRsaKeyRepository;
    private final RsaPrivateKeyConverter rsaPrivateKeyConverter;
    private final RsaPublicKeyConverter rsaPublicKeyConverter;

    public void deleteRsaKeyPair(String id){
        jpaRsaKeyRepository.deleteById(Long.valueOf(id));
    }

    @Override
    public boolean isRsaKeyPairInitialized( ){
        return jpaRsaKeyRepository.findAllOrderByCreatedAtDesc().isEmpty();
    }

    public void rotateSigningKeys(){
        RsaKeyPair nextRsaKeyPairRotation = generateNewRsaKeyPair();
        jpaRsaKeyRepository.save(nextRsaKeyPairRotation);
    }

    private RsaKeyPair generateNewRsaKeyPair(){

        KeyPair keyPair = createNewKeyPair();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();

        ByteArrayOutputStream baosPrivate = new ByteArrayOutputStream();
        ByteArrayOutputStream baosPublic = new ByteArrayOutputStream();
        try {
            rsaPrivateKeyConverter.serialize(rsaPrivateKey, baosPrivate);
            rsaPublicKeyConverter.serialize(rsaPublicKey, baosPublic);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return RsaKeyPair
                .builder()
                .createdAt(Instant.now())
                .rsaPrivateKey(baosPrivate.toString())
                .rsaPublicKey(baosPublic.toString())
                .build();
    }

    public List<RsaKeyPairDto> getAllRsaKeyPairs(){
        return jpaRsaKeyRepository.findAllOrderByCreatedAtDesc().stream().map((RsaKeyPair rsaKeyPair) -> {
            try {
                return RsaKeyPairDto
                        .builder()
                        .id(String.valueOf(rsaKeyPair.getId()))
                        .publicKey(rsaPublicKeyConverter.deserializeFromByteArray(rsaKeyPair.getRsaPublicKey().getBytes()))
                        .privateKey(rsaPrivateKeyConverter.deserializeFromByteArray(rsaKeyPair.getRsaPrivateKey().getBytes()))
                        .build();
            } catch (IOException e) {
                throw new RuntimeException("Unable to deserialize from String to either RSA PUBLIC-PRIVATE KEY",e);
            }
        }).collect(Collectors.toUnmodifiableList());
    }


    private KeyPair createNewKeyPair(){
        try{
            return KeyPairGenerator.getInstance("RSA").generateKeyPair();
        }catch (Exception e){
            throw new IllegalStateException("Could not generate new key pair to sign the oauth2 tokens");
        }
    }




}
