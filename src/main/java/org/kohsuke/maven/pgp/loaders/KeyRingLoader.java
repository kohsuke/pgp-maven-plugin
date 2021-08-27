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
import java.io.InputStream;
import java.util.Iterator;
import java.util.Map;

/**
 * Loads a key from a keyring.
 * 
 * @author Kohsuke Kawaguchi
 */
@Component(role=SecretKeyLoader.class,hint="keyring")
public class KeyRingLoader extends SecretKeyLoader {
    public PGPSecretKey load(PgpMojo mojo, String specifier) throws IOException {
        Map<String,String> opts = parseQueryParameters(specifier);

        File keyFile;
        if (opts.containsKey("keyring")) {
            keyFile = new File(opts.get("keyring"));
        } else {
            keyFile = new File(new File(System.getProperty("user.home")),".gnupg/secring.gpg");
        }
        if (!keyFile.exists())
            throw new IOException("No such key ring file exists: "+keyFile);


        String id = opts.get("id");

        InputStream in = PGPUtil.getDecoderStream(new FileInputStream(keyFile));
        try {
            PGPObjectFactory pgpFact = new PGPObjectFactory(in, new BcKeyFingerprintCalculator());

            Object              obj;
            while ((obj = pgpFact.nextObject()) != null)
            {
                if (!(obj instanceof PGPSecretKeyRing))
                    throw new IOException("Expecting a secret key but found "+obj);

                PGPSecretKeyRing key = (PGPSecretKeyRing)obj;

                if (id==null)
                    return key.getSecretKey();  // pick up the first one if no key ID specifier is given

                Iterator jtr = key.getSecretKeys();
                while (jtr.hasNext()) {
                    PGPSecretKey skey = (PGPSecretKey) jtr.next();

                    if (id.equalsIgnoreCase(Long.toHexString(skey.getPublicKey().getKeyID() & 0xFFFFFFFF)))
                        return skey;

                    for (Iterator ktr=skey.getUserIDs(); ktr.hasNext(); ) {
                        String s = (String) ktr.next();
                        if (s.contains(id))
                            return skey;
                    }

                }
            }

            throw new IOException("No key that matches "+id+" was found in "+keyFile);
        } finally {
            in.close();
        }
    }

    public static void main(String[] args) throws IOException {
        new KeyRingLoader().load(null, "id=D50582E6");
    }
}
