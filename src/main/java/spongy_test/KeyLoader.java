package spongy_test;

import org.spongycastle.openssl.PEMKeyPair;
import org.spongycastle.openssl.PEMParser;
import org.spongycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class KeyLoader {

    public static PublicKey loadPublicKey(String encodedKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        byte[] content = Base64.getDecoder().decode(encodedKey);
        String decoded = new String(content);

        String keyContent = Arrays.stream(decoded.split("\n"))
                .filter(s -> !s.contains("---"))
                .reduce((a, b) -> a + b)
                .get();

        byte[] decodedContent = Base64.getDecoder().decode(keyContent);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(decodedContent);
        return KeyFactory.getInstance("EC").generatePublic(spec);
    }

    public static PrivateKey loadPrivateKey(String encodedKey) throws IOException {
        byte[] content = Base64.getDecoder().decode(encodedKey);
        String decoded = new String(content);

        Reader rdr = new StringReader(decoded);
        Object parsed = new PEMParser(rdr).readObject();

        KeyPair keyPair = new JcaPEMKeyConverter()
                .getKeyPair((PEMKeyPair) parsed);

        return keyPair.getPrivate();
    }

}
