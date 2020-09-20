package org.kohsuke.maven.pgp.loaders;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.maven.plugin.MojoExecutionException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.codehaus.plexus.component.annotations.Component;
import org.kohsuke.maven.pgp.PgpMojo;
import org.kohsuke.maven.pgp.SecretKeyLoader;

/**
 * Specifies a secret key directly, as a base64-encoded literal
 * 
 * @author David Arnold
 */
@Component(role = SecretKeyLoader.class, hint = "literal")
public class LiteralSecretKeyLoader extends SecretKeyLoader {

	@Override
	public PGPSecretKey load(PgpMojo mojo, String encodedKey) throws IOException, MojoExecutionException {
		InputStream in = new ByteArrayInputStream(encodedKey.getBytes());		
        try {
            PGPObjectFactory pgpF = new PGPObjectFactory(PGPUtil.getDecoderStream(in));
            Object o = pgpF.nextObject();
            if (!(o instanceof PGPSecretKeyRing)) {
                throw new IOException("Literal doesn't contain PGP private key");
            }
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing) o;
            return keyRing.getSecretKey();
        } finally {
            in.close();
        }
	}

}
