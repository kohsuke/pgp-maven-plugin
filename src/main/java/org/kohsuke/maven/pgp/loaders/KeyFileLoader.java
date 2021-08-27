package org.kohsuke.maven.pgp.loaders;

import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.codehaus.plexus.component.annotations.Component;
import org.kohsuke.maven.pgp.PgpMojo;
import org.kohsuke.maven.pgp.SecretKeyLoader;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * Loads PGP secret key from the exported key file,
 * which normally ends with the ".asc" extension and has
 * a "-----BEGIN PGP PRIVATE KEY BLOCK-----" header.
 *
 * @author Kohsuke Kawaguchi
 */
@Component(role=SecretKeyLoader.class,hint="keyfile")
public class KeyFileLoader extends SecretKeyLoader {
    public PGPSecretKey load(PgpMojo mojo, String keyFile) throws IOException {
        FileInputStream in = new FileInputStream(new File(keyFile));
        try {
            PGPObjectFactory pgpF = new PGPObjectFactory(PGPUtil.getDecoderStream(in), new BcKeyFingerprintCalculator());
            Object o = pgpF.nextObject();
            if (!(o instanceof PGPSecretKeyRing)) {
                throw new IOException(keyFile+" doesn't contain PGP private key");
            }
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing) o;
            return keyRing.getSecretKey();
        } finally {
            in.close();
        }
    }
}
