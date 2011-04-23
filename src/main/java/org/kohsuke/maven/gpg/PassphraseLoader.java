package org.kohsuke.maven.gpg;

import org.apache.maven.plugin.MojoExecutionException;
import org.bouncycastle.openpgp.PGPSecretKey;

import java.io.Closeable;
import java.io.IOException;
import java.util.Iterator;

/**
 * Loads a pass-phrase for the specified key.
 *
 * <p>
 * Implementations should be plexus components, and its role hint is
 * matched against the passphrase loader configuration parameter's scheme portion.
 *
 * @author Kohsuke Kawaguchi
 */
public abstract class PassphraseLoader {
    /**
     * Obtains the pass-phrase.
     *
     * @param mojo
     *      Mojo that's driving the execution.
     * @param secretKey
     *      The key for which the pass-phrase is retrieved.
     * @param specifier
     *      The pass phrase loader parameter specified to {@link PgpMojo}, except the first scheme part.
     *      If the loader needs to take additional parameters, it should do so from this string.
     *
     * @return
     *      the passphrase.
     */
    public abstract String load(PgpMojo mojo, PGPSecretKey secretKey, String specifier) throws IOException, MojoExecutionException;
}
