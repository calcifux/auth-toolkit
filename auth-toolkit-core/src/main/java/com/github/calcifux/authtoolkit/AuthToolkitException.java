package com.github.calcifux.authtoolkit;

/**
 * Base unchecked exception for the toolkit. Distinguishes an INFRASTRUCTURE failure
 * (this exception) from "no/!invalid credential" (which adapters signal as an empty
 * result, not an exception) — so a JWKS endpoint being down is never silently
 * downgraded to "anonymous".
 */
public class AuthToolkitException extends RuntimeException {

    public AuthToolkitException(String message) {
        super(message);
    }

    public AuthToolkitException(String message, Throwable cause) {
        super(message, cause);
    }
}
