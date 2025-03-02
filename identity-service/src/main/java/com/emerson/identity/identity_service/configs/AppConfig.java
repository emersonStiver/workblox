package com.emerson.identity.identity_service.configs;

import com.emerson.identity.identity_service.repositories.JpaRsaKeyRepository;
import com.emerson.identity.identity_service.services.contracts.RsaKeyPairService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zaxxer.hikari.HikariDataSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.encrypt.AesBytesEncryptor;
import org.springframework.security.crypto.encrypt.BytesEncryptor;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Configuration
public class AppConfig {
    @Bean
    public ObjectMapper mapper(){
        return new ObjectMapper();
    }

    @Bean
    public DataSource dataSource(){
        /*
            HikariCP is a fast, efficient, and lightweight JDBC connection pool.
            Spring Boot uses HikariCP by default when working with databases.
            It reuses database connections instead of opening a new one for every request.
            You can configure it via application.properties or manually using a DataSource bean.
         */
        HikariDataSource dataSource = new HikariDataSource();
        dataSource.setJdbcUrl("jdbc:mysql://localhost:3306/identity?useSSL=false&serverTimezone=UTC");
        dataSource.setUsername("root");
        dataSource.setPassword("root");
        dataSource.setDriverClassName("come.mysql.cj.jdbc.Driver");
        dataSource.setMaximumPoolSize(10);
        dataSource.setMinimumIdle(5);
        dataSource.setIdleTimeout(30000);
        dataSource.setConnectionTimeout(20000);
        dataSource.setMaxLifetime(1800000);
        return dataSource;
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SpringTemplateEngine springTemplateEngine(){
        ClassLoaderTemplateResolver templateResolver = new ClassLoaderTemplateResolver();
        templateResolver.setPrefix("/templates/");
        templateResolver.setSuffix("/.html");
        templateResolver.setTemplateMode(TemplateMode.HTML);
        templateResolver.setCharacterEncoding(StandardCharsets.UTF_8.name());
        templateResolver.setCacheable(false);

        SpringTemplateEngine springTemplateEngine = new SpringTemplateEngine();
        springTemplateEngine.addTemplateResolver(templateResolver);
        return springTemplateEngine;
    }

    @Bean
    public BytesEncryptor getBytesEncryptor(@Value ("${jwt.secret.key}") String jwtSecret, @Value("${jwt.encryptor.salt}") String salt){
        /*
        This impl encrypts and decrypts bytes[] using symmetric data encryption
        SecretKey secretKey = new SecretKeySpec(Base64.getDecoder().decode(jwtSecret.trim()), "AES");
        BytesKeyGenerator ivGenerator = KeyGenerators.secureRandom(12);
        return new AesBytesEncryptor(secretKey, ivGenerator, AesBytesEncryptor.CipherAlgorithm.GCM);
         */
        return Encryptors.stronger(jwtSecret, salt);
    }

    @Bean
    public TextEncryptor getTextEncryptor( @Value("${jwt.encryptor.password}")String password, @Value("${jwt.encryptor.salt}") String salt) {
        return Encryptors.text(password, salt);
    }

    @Bean
    ApplicationRunner initializeRsaKeyPars(RsaKeyPairService rsaKeyPairService){
        return (r) ->{
            if(!rsaKeyPairService.isRsaKeyPairInitialized()){
                rsaKeyPairService.rotateSigningKeys();
            }
        };
    }

}
