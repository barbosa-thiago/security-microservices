package com.thiago.valhallaproject.security.token.converter;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import com.thiago.valhallaproject.property.JwtConfiguration;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

import java.text.ParseException;

@Slf4j
@Service
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class TokenConverter {
    private final JwtConfiguration jwtConfiguration;

    public String decryptToken(String encryptedToken){
        log.info("Decrypting token");
        try {
            JWEObject jweObject = JWEObject.parse(encryptedToken);
            DirectDecrypter directDecrypter = new DirectDecrypter(jwtConfiguration.getPrivateKey().getBytes());
            jweObject.decrypt(directDecrypter);
            log.info("Token decrypted, returning signed token. . . ");
            return jweObject.getPayload().toSignedJWT().serialize();
        } catch (ParseException |JOSEException e) {
            e.printStackTrace();
        }
        return null;
    }
    public void validateTokenSignature(String signedToken){
        log.info("Starting method to validate token signature");

        try {
            SignedJWT signedJWT = SignedJWT.parse(signedToken);
            log.info("Token parsed. Retrieving private key from signed token");
            RSAKey rsaPublicKey = RSAKey.parse(signedJWT.getHeader().getJWK().toJSONObject());
            if(!signedJWT.verify(new RSASSAVerifier(rsaPublicKey)))
                throw new AccessDeniedException("Invalid token signature");
        } catch (JOSEException | ParseException e) {
            e.printStackTrace();
        }
        log.info("The token has a valid signature");
    }
}
