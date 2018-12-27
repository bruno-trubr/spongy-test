package spongy_test;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.Date;

import static io.jsonwebtoken.SignatureAlgorithm.ES256;
import static java.time.temporal.ChronoUnit.SECONDS;

public class KeyLoaderTest {

    private final String publicKey = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUFvRFFnQUVXaVM5dVN2NE1rTUpvWGh0ZUV3WS9GMFFiQVBUbmY2awpRNmhrYzAvcVJ5N3RRQ1dNQUU2REZpUFBGTDlwbGlUNGhDZklLYTJ3RzRxaGkzNlZXQWJZV0E9PQotLS0tLUVORCBQVUJMSUMgS0VZLS0tLS0=";
    private final String privateKey = "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IUUNBUUVFSUt2WkxPRDZOaDcwZk02bWZJM1A4WlhPdFFnNDV3QkxDb1JDVGROdm9IQUlvQWNHQlN1QkJBQUsKb1VRRFFnQUVXaVM5dVN2NE1rTUpvWGh0ZUV3WS9GMFFiQVBUbmY2a1E2aGtjMC9xUnk3dFFDV01BRTZERmlQUApGTDlwbGlUNGhDZklLYTJ3RzRxaGkzNlZXQWJZV0E9PQotLS0tLUVORCBFQyBQUklWQVRFIEtFWS0tLS0t";

    @Test
    public void verification_should_succeed() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        String token = generateSignedIdentityToken("did");
        IdentityToken identityToken = new IdentityToken(token);
        PublicKey pubKey = KeyLoader.loadPublicKey(publicKey);
        identityToken.verifySignature(pubKey);
    }

    private String generateSignedIdentityToken(String did) throws IOException {
        PrivateKey keyToSign = KeyLoader.loadPrivateKey(privateKey);

        IdentityData identityData = new IdentityData(new String(did));
        String subject = new ObjectMapper().writeValueAsString(identityData);

        Instant expirationInstant = Instant.now().plus(10L, SECONDS);
        Date expirationDate = Date.from(expirationInstant);

        return Jwts.builder()
                .setSubject(subject)
                .setExpiration(expirationDate)
                .signWith(keyToSign, ES256)
                .compact();
    }

}