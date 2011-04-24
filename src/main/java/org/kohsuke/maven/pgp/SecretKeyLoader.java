package org.kohsuke.maven.pgp;

import org.apache.maven.plugin.MojoExecutionException;
import org.bouncycastle.openpgp.PGPSecretKey;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Loads the secret key (a public key/private key pair) to generate a signature with.
 *
 * <p>
 * Implementations should be plexus components, and its role hint is
 * matched against the passphrase loader configuration parameter's scheme portion.
 *
 * @author Kohsuke Kawaguchi
 */
public abstract class SecretKeyLoader {
    /**
     * @param mojo
     *      Mojo that's driving the execution.
     * @param specifier
     *      The secretkey loader parameter specified to {@link PgpMojo}, except the first scheme part.
     *      If the loader needs to take additional parameters, it should do so from this string.
     */
    public abstract PGPSecretKey load(PgpMojo mojo, String specifier) throws IOException, MojoExecutionException;

    /**
     * Parses "a=b&c=d&..." into a map.
     * Useful for creating a structure in the specifier argument to the load method.
     */
    protected final Map<String,String> parseQueryParameters(String specifier) {
        Map<String,String> opts = new HashMap<String, String>();
        for (String token : specifier.split("&")) {
            int idx = token.indexOf('=');
            if (idx<0)  opts.put(token,"");
            else        opts.put(token.substring(0,idx),token.substring(idx+1));
        }
        return opts;
    }
}
