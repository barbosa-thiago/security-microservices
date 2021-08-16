package com.thiago.valhallaproject.security.token.creator;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.thiago.valhallaproject.domain.ApplicationUser;
import com.thiago.valhallaproject.property.JwtConfiguration;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.UUID;

import static java.util.stream.Collectors.toList;

@Service
@Slf4j
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class TokenCreator {
    private final JwtConfiguration jwtConfiguration;

    public SignedJWT createSignedJwt(Authentication authentication) {
        log.info("Starting to create signed JWT");
        ApplicationUser applicationUser = (ApplicationUser) authentication.getPrincipal();
        JWTClaimsSet jwtClaimsSet = createJwtClaimsSet(authentication, applicationUser);
        KeyPair rsaKeys = generateKeypair();

        log.info("Generating JWK from rsa keys");

        JWK jwk = new RSAKey.Builder((RSAPublicKey) rsaKeys.getPublic()).keyID(UUID.randomUUID().toString()).build();

        SignedJWT signingJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256)
                .jwk(jwk).type(JOSEObjectType.JWT).build(), jwtClaimsSet);

        log.info("Signing the token with the rsa keys");

        RSASSASigner signer = new RSASSASigner(rsaKeys.getPrivate());

        try {
            signingJWT.sign(signer);
        } catch (JOSEException e) {
            e.printStackTrace();
        }
        log.info("Serialized token: {}",signingJWT.serialize());
        return signingJWT;

    }

    public JWTClaimsSet createJwtClaimsSet(Authentication auth, ApplicationUser applicationUser){
        return new JWTClaimsSet.Builder()
                .subject(applicationUser.getUsername())
                .claim("authorities", auth.getAuthorities()
                        .stream().map(GrantedAuthority::getAuthority)
                        .collect(toList()))
                .issuer("http://academy.devdojo")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + (jwtConfiguration.getExpiration() * 1000)))
                .build();
    }

    public KeyPair generateKeypair(){
        log.info("Generating keys");
        try {
            KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
            keygen.initialize(2048);
            return keygen.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    public String encriptToken(SignedJWT signedJWT){
        log.info("Starting to encripting the token");
        String encriptedToken = "";
        try {
            DirectEncrypter directEncrypter = new DirectEncrypter(jwtConfiguration.getPrivateKey().getBytes());
            JWEObject jweObject = new JWEObject(new JWEHeader.Builder(new JWEAlgorithm("dir"),
                    EncryptionMethod.A128CBC_HS256).contentType("JWT").build(), new Payload(signedJWT));
            log.info("Encripting the token woth system's private key");
            jweObject.encrypt(directEncrypter);
            log.info("Token encripted");
            encriptedToken = jweObject.serialize();
        } catch (JOSEException e) {
            e.printStackTrace();
        }
        return encriptedToken;
    }
}
