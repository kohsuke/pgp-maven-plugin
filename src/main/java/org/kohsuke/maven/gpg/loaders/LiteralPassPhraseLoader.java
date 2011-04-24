package org.kohsuke.maven.gpg.loaders;

import org.apache.maven.plugin.MojoExecutionException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.codehaus.plexus.component.annotations.Component;
import org.kohsuke.maven.gpg.PassphraseLoader;
import org.kohsuke.maven.gpg.PgpMojo;

import java.io.IOException;
import java.util.Collections;
import java.util.Iterator;

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
