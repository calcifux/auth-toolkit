package com.github.calcifux.authtoolkit;

/**
 * Thrown when a token is present but fails verification (bad signature, wrong issuer
 * or audience, expired, malformed). Distinct from an absent credential: a present-but-
 * invalid token is a 401, not "anonymous, try the next adapter".
 */
public class TokenVerificationException extends AuthToolkitException {

    public TokenVerificationException(String message) {
        super(message);
    }

    public TokenVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
