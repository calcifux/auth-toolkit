package com.github.calcifux.authtoolkit.jwt;

import java.nio.file.Path;

/**
 * Command-line key generator — the portable, no-openssl-needed way to mint the RS256 signing
 * keypair (think {@code php artisan passport:keys}). Useful on machines without openssl, or
 * wired into a build/Make target so juniors run ONE command and get ready-to-use key files.
 *
 * <pre>{@code
 * java -cp auth-toolkit-core.jar com.github.calcifux.authtoolkit.jwt.KeyGenCli \
 *      keys/private.pem keys/public.pem 2048
 * }</pre>
 *
 * <p>Arguments: {@code <privatePath> <publicPath> [bits]} — defaults
 * {@code keys/private.pem keys/public.pem 2048}. Afterwards, git-ignore the private key and
 * point your config at the two paths.</p>
 */
public final class KeyGenCli {

    private KeyGenCli() {
        // Entry point only.
    }

    public static void main(String[] args) {
        String privatePath = args.length > 0 ? args[0] : "keys/private.pem";
        String publicPath = args.length > 1 ? args[1] : "keys/public.pem";
        int bits = args.length > 2 ? Integer.parseInt(args[2]) : RsaKeyGenerator.DEFAULT_KEY_SIZE;

        RsaKeyGenerator.writeKeypair(bits, Path.of(privatePath), Path.of(publicPath));

        System.out.println("RSA " + bits + "-bit keypair written:");
        System.out.println("  private (SECRET, chmod 600): " + privatePath);
        System.out.println("  public  (shareable / JWKS):  " + publicPath);
        System.out.println("Next: git-ignore the private key and point your config at these paths.");
    }
}
