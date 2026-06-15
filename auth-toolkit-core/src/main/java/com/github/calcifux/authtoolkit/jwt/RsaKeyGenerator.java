package com.github.calcifux.authtoolkit.jwt;

import com.github.calcifux.authtoolkit.AuthToolkitException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Set;

/**
 * Generates an RSA keypair and writes it as PEM files — the kit's equivalent of
 * {@code php artisan passport:keys}. Output formats match what {@link RsaKeys} reads:
 * private = unencrypted PKCS#8 ({@code -----BEGIN PRIVATE KEY-----}), public = X.509 SPKI
 * ({@code -----BEGIN PUBLIC KEY-----}).
 *
 * <p>The private key file is written {@code 0600} (owner read/write only) on POSIX systems.
 * Keep it OUT of git and out of the jar; commit only the public key (or serve it via JWKS).</p>
 */
public final class RsaKeyGenerator {

    /** RFC 7518 floor for RS256. Use 3072 for ~128-bit security if you want it stronger. */
    public static final int DEFAULT_KEY_SIZE = 2048;

    private RsaKeyGenerator() {
        // Utility class.
    }

    /** Generates a {@code bits}-size RSA keypair (must be >= 2048). */
    public static KeyPair generate(int bits) {
        if (bits < 2048) {
            throw new AuthToolkitException("RSA key size must be >= 2048 (RS256 minimum), got " + bits);
        }
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(bits);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new AuthToolkitException("RSA key generation failed", e);
        }
    }

    /**
     * Generates a keypair and writes the two PEM files, creating parent directories as needed.
     * The private file gets {@code 0600} permissions where the OS supports it.
     */
    public static void writeKeypair(int bits, Path privateKeyOut, Path publicKeyOut) {
        KeyPair pair = generate(bits);
        // RSAPrivateKey.getEncoded() is PKCS#8; RSAPublicKey.getEncoded() is X.509 SPKI — exactly
        // the formats RsaKeys reads back. No BouncyCastle needed.
        writePem(privateKeyOut, "PRIVATE KEY", pair.getPrivate().getEncoded(), true);
        writePem(publicKeyOut, "PUBLIC KEY", pair.getPublic().getEncoded(), false);
    }

    private static void writePem(Path out, String label, byte[] der, boolean ownerOnly) {
        // PEM = armor + base64(DER) wrapped at 64 columns.
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der);
        String pem = "-----BEGIN " + label + "-----\n" + base64 + "\n-----END " + label + "-----\n";
        try {
            if (out.getParent() != null) {
                Files.createDirectories(out.getParent());
            }
            Files.writeString(out, pem);
            if (ownerOnly) {
                restrictToOwner(out);
            }
        } catch (IOException e) {
            throw new AuthToolkitException("Cannot write key file: " + out, e);
        }
    }

    /** Best-effort {@code chmod 600}; silently skipped on non-POSIX filesystems (e.g. Windows). */
    private static void restrictToOwner(Path path) {
        try {
            Set<PosixFilePermission> ownerReadWrite =
                    EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(path, ownerReadWrite);
        } catch (UnsupportedOperationException | IOException ignored) {
            // Non-POSIX FS: the deployer must lock the file down via the OS.
        }
    }
}
