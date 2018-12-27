package spongy_test;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;

import java.io.IOException;
import java.security.PublicKey;

import static io.jsonwebtoken.JwtParser.SEPARATOR_CHAR;

public class IdentityToken {

    private final String token;

    public IdentityToken(String token) {
        this.token = token;
    }

    public IdentityData getSubject() throws IOException {
        Integer lastSeparatorIndex = token.lastIndexOf(SEPARATOR_CHAR);
        String withoutSignature = token.substring(0, lastSeparatorIndex + 1);

        String subject = Jwts.parser()
                .parseClaimsJwt(withoutSignature)
                .getBody()
                .getSubject();

        return new ObjectMapper().readValue(subject, IdentityData.class);
    }

    public void verifySignature(PublicKey key) {
        String _token = token;

        if (!Jwts.parser().isSigned(_token)) {
            _token += "fake-signature";
        }

        Jwts.parser().setSigningKey(key).parse(_token);
    }

}
