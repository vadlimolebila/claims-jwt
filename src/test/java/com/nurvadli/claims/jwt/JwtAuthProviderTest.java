package com.nurvadli.claims.jwt;

import com.nurvadli.claims.jwt.config.JWTAuthProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * @author Nurvadli
 */
public class JwtAuthProviderTest {

    private static final Logger logger = LogManager.getLogger();

    /**
     * create a simple JWT, decode it, and assert the claims
     */
    @Test
    public void createAndDecodeJwt() {
        String jwtId = "nurvadli";
        String jwtIssuer = "test-jwt";
        String jwtSubject = "BE-Developer";
        int jwtTimeToLive = 800000;

        String  jwt = JWTAuthProvider.create(jwtId, jwtIssuer, jwtSubject, jwtTimeToLive);

        logger.info("jwt = \""+ jwt.toString() + "\"");

        Claims claims = JWTAuthProvider.decodeJWT(jwt);

        logger.info("claims = "+ claims.toString());

        assertEquals(jwtId, claims.getId());
    }

    /**
     * Attempt to decode a bougs JWT and expect an exception
     */
    @Test(expected = MalformedJwtException.class)
    public void decodeShoudlFail() {
        String notAJwt = "This is not a JWT";

        //This will expected exception listed above
        Claims claims = JWTAuthProvider.decodeJWT(notAJwt);
    }

    /**
     * create a simple JWT, modify it and try to decode it
     */
    @Test(expected = SignatureException.class)
    public void createAndDecodeTamperedJWT() {
        String jwtId = "nurvadli";
        String jwtIssuer = "test-jwt";
        String jwtSubject = "BE-Developer";
        int jwtTimeToLive = 800000;

        String jwt = JWTAuthProvider.create(
                jwtId, // claim = jti
                jwtIssuer, // claim = iss
                jwtSubject, // claim = sub
                jwtTimeToLive // used to calculate expiration (claim = exp)
        );

        logger.info("jwt = \"" + jwt.toString() + "\"");

        // tamper with the JWT

        StringBuilder tamperedJwt = new StringBuilder(jwt);
        tamperedJwt.setCharAt(22, 'I');

        logger.info("tamperedJwt = \"" + tamperedJwt.toString() + "\"");

        assertNotEquals(jwt, tamperedJwt);

        // this will fail with a SignatureException

        JWTAuthProvider.decodeJWT(tamperedJwt.toString());
    }
}
