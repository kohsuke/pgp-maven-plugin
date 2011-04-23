package org.kohsuke.maven.gpg;

import org.apache.maven.plugin.MojoExecutionException;
import org.bouncycastle.openpgp.PGPSecretKey;

import java.io.IOException;

/**
 * @author Kohsuke Kawaguchi
 */
public abstract class SecretKeyLoader {
    public abstract PGPSecretKey load(PgpMojo mojo, String specifier) throws IOException, MojoExecutionException;
}
