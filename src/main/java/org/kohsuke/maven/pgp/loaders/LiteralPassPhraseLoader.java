package org.kohsuke.maven.pgp.loaders;

import org.apache.maven.plugin.MojoExecutionException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.codehaus.plexus.component.annotations.Component;
import org.kohsuke.maven.pgp.PassphraseLoader;
import org.kohsuke.maven.pgp.PgpMojo;

import java.io.IOException;

/**
 * Specifies a pass phrase directly as literal.
 * 
 * @author Kohsuke Kawaguchi
 */
@Component(role=PassphraseLoader.class,hint="literal")
public class LiteralPassPhraseLoader extends PassphraseLoader {
    @Override
    public String load(PgpMojo mojo, PGPSecretKey secretKey, String specifier) throws IOException, MojoExecutionException {
        return specifier;
    }
}
