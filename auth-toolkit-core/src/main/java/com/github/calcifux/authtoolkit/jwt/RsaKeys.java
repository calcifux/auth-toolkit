package com.github.calcifux.authtoolkit.jwt;

import com.github.calcifux.authtoolkit.AuthToolkitException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Loads RSA keys from PEM FILES on the filesystem (absolute or working-dir-relative path —
 * NOT the classpath) and builds the Nimbus {@link RSAKey} used to sign or verify RS256 tokens.
 *
 * <p><b>Why the filesystem, never the classpath:</b> a private signing key must live OUTSIDE
 * the deployable jar so it can be {@code chmod 600}, kept out of git, and rotated without a
 * rebuild. Read its PATH from config ({@code .env} / {@code application.yml}); never bake the
 * key into {@code src/main/resources}. The public key is safe to share (commit it, or serve it
 * via {@link #publicJwksJson}).</p>
 *
 * <p><b>Pure JDK — no BouncyCastle.</b> The keys must be in the standard formats that
 * {@code openssl genpkey} / {@code openssl rsa -pubout} (and this kit's {@link RsaKeyGenerator})
 * produce: private = unencrypted PKCS#8 ({@code -----BEGIN PRIVATE KEY-----}), public = X.509
 * SubjectPublicKeyInfo ({@code -----BEGIN PUBLIC KEY-----}). A legacy PKCS#1 private key
 * ({@code BEGIN RSA PRIVATE KEY}) must be converted once:
 * {@code openssl pkcs8 -topk8 -nocrypt -in pkcs1.pem -out pkcs8.pem}.</p>
 */
public final class RsaKeys {

    private RsaKeys() {
        // Utility class.
    }

    /** Reads an unencrypted PKCS#8 private key ({@code BEGIN PRIVATE KEY}) from a PEM file. */
    public static RSAPrivateKey readPrivateKeyPem(String path) {
        byte[] der = derBytes(path, "PRIVATE KEY");
        try {
            return (RSAPrivateKey) KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (Exception e) {
            throw new AuthToolkitException("Not a valid PKCS#8 RSA private key: " + cleanPath(path)
                    + " (convert PKCS#1 with: openssl pkcs8 -topk8 -nocrypt)", e);
        }
    }

    /** Reads an X.509 SubjectPublicKeyInfo public key ({@code BEGIN PUBLIC KEY}) from a PEM file. */
    public static RSAPublicKey readPublicKeyPem(String path) {
        byte[] der = derBytes(path, "PUBLIC KEY");
        try {
            return (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception e) {
            throw new AuthToolkitException("Not a valid X.509 RSA public key: " + cleanPath(path), e);
        }
    }

    /**
     * Builds the SIGNING key (private + public + {@code keyId}) for {@link JwtIssuer#rsa},
     * reading both PEM files from the filesystem. The {@code keyId} is stamped into every token
     * header so verifiers can rotate by {@code kid}.
     */
    public static RSAKey signingKey(String privateKeyPath, String publicKeyPath, String keyId) {
        RSAPublicKey publicKey = readPublicKeyPem(publicKeyPath);
        RSAPrivateKey privateKey = readPrivateKeyPem(privateKeyPath);
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(blankToNull(keyId))
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .build();
    }

    /**
     * Builds the VERIFICATION key (public only + {@code keyId}) for verifying RS256 tokens
     * against a single local public key, reading the public PEM file from the filesystem.
     */
    public static RSAKey verificationKey(String publicKeyPath, String keyId) {
        return new RSAKey.Builder(readPublicKeyPem(publicKeyPath))
                .keyID(blankToNull(keyId))
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .build();
    }

    /**
     * The JWKS JSON ({@code {"keys":[...]}}) of one or more PUBLIC keys, ready to serve at
     * {@code GET /.well-known/jwks.json} so other services can verify your tokens without a
     * shared secret. Only public params are emitted — the private {@code d,p,q,...} are stripped.
     */
    public static String publicJwksJson(RSAKey... keys) {
        List<JWK> publicOnly = new ArrayList<>();
        for (RSAKey key : keys) {
            publicOnly.add(key.toPublicJWK());
        }
        return new JWKSet(publicOnly).toString();
    }

    // --- internals -------------------------------------------------------

    /** Read the PEM text, strip the BEGIN/END armor + all whitespace, Base64-decode to DER. */
    private static byte[] derBytes(String path, String pemLabel) {
        String pem;
        try {
            pem = Files.readString(Path.of(cleanPath(path)));
        } catch (Exception e) {
            throw new AuthToolkitException("Cannot read key file: " + cleanPath(path)
                    + " (use an absolute or working-dir-relative path, not the classpath)", e);
        }
        String body = pem
                .replace("-----BEGIN " + pemLabel + "-----", "")
                .replace("-----END " + pemLabel + "-----", "")
                .replaceAll("\\s", ""); // drop newlines/CRLF/spaces so Base64 decodes cleanly
        try {
            return Base64.getDecoder().decode(body);
        } catch (IllegalArgumentException e) {
            throw new AuthToolkitException("Malformed PEM (expected " + pemLabel + "): " + cleanPath(path), e);
        }
    }

    /** Tolerate a {@code file:} prefix and surrounding whitespace so config values "just work". */
    private static String cleanPath(String path) {
        if (path == null) {
            throw new AuthToolkitException("Key path is null");
        }
        String trimmed = path.trim();
        return trimmed.startsWith("file:") ? trimmed.substring("file:".length()) : trimmed;
    }

    private static String blankToNull(String value) {
        return (value == null || value.isBlank()) ? null : value;
    }
}
