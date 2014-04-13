package org.kohsuke.maven.pgp;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPUtil;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

/**
 * Generates a PGP signature.
 *
 * @author Kohsuke Kawaguchi
 */
class Signer {
    private final PGPPrivateKey privateKey;
    private final PGPPublicKey publicKey;

    Signer(PGPPrivateKey privateKey, PGPPublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    Signer(PGPSecretKey secretKey, char[] passphrase) {
        try {
            this.privateKey = secretKey.extractPrivateKey(passphrase,PROVIDER);
            if (this.privateKey == null)
                throw new IllegalArgumentException("Unsupported signing key"
                    + (secretKey.getKeyEncryptionAlgorithm() == PGPPublicKey.RSA_SIGN ?
                       ": RSA (sign-only) is unsupported by BouncyCastle" : ""));
            this.publicKey = secretKey.getPublicKey();
        } catch (PGPException e) {
            throw new IllegalArgumentException("Passphrase is incorrect",e);
        }
    }

    PGPSignature sign(InputStream in) throws IOException, PGPException, GeneralSecurityException {
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(publicKey.getAlgorithm(), PGPUtil.SHA1, PROVIDER);
        sGen.initSign(PGPSignature.BINARY_DOCUMENT, privateKey);

        byte[] buf = new byte[4096];
        int len;
        while ((len=in.read(buf))>=0)
            sGen.update(buf,0,len);
        return sGen.generate();
    }

    /**
     * Generates the signature of the given input stream as an ASCII file into the given output stream.
     */
    void sign(InputStream in, OutputStream signatureOutput) throws PGPException, IOException, GeneralSecurityException {
        BCPGOutputStream bOut = new BCPGOutputStream(new ArmoredOutputStream(signatureOutput));
        sign(in).encode(bOut);
        bOut.close();
    }

    void sign(File in, File signature) throws PGPException, IOException, GeneralSecurityException {
        InputStream fin = new BufferedInputStream(new FileInputStream(in));
        OutputStream out = new BufferedOutputStream(new FileOutputStream(signature));
        try {
            sign(fin,out);
        } finally {
            fin.close();
            out.close();
        }
    }

    /*package*/ static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();
}
