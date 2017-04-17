package org.spongycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;

import org.spongycastle.asn1.DERNull;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.DigestInfo;
import org.spongycastle.jcajce.util.JcaJceHelper;
import org.spongycastle.tls.DigitallySigned;
import org.spongycastle.tls.SignatureAlgorithm;
import org.spongycastle.tls.SignatureAndHashAlgorithm;
import org.spongycastle.tls.TlsUtils;
import org.spongycastle.tls.crypto.TlsVerifier;

/**
 * Operator supporting the verification of RSA signatures.
 */
public class JcaTlsRSAVerifier
    implements TlsVerifier
{
    private final JcaJceHelper helper;
    protected RSAPublicKey pubKeyRSA;

    public JcaTlsRSAVerifier(RSAPublicKey pubKeyRSA, JcaJceHelper helper)
    {
        if (pubKeyRSA == null)
        {
            throw new IllegalArgumentException("'pubKeyRSA' cannot be null");
        }

        this.pubKeyRSA = pubKeyRSA;
        this.helper = helper;
    }

    public boolean verifySignature(DigitallySigned signedParams, byte[] hash)
    {
        SignatureAndHashAlgorithm algorithm = signedParams.getAlgorithm();

        try
        {
            Signature signer = helper.createSignature("NoneWithRSA");
            signer.initVerify(pubKeyRSA);
            if (algorithm != null)
            {
                if (algorithm.getSignature() != SignatureAlgorithm.rsa)
                {
                    throw new IllegalStateException();
                }

            /*
             * RFC 5246 4.7. In RSA signing, the opaque vector contains the signature generated
             * using the RSASSA-PKCS1-v1_5 signature scheme defined in [PKCS1].
             */

                try
                {
                    byte[] digInfo = new DigestInfo(new AlgorithmIdentifier(TlsUtils.getOIDForHashAlgorithm(algorithm.getHash()), DERNull.INSTANCE), hash).getEncoded();
                    signer.update(digInfo, 0, digInfo.length);
                }
                catch (IOException e)
                {
                    e.printStackTrace();  // TODO
                }
            }
            else
            {
            /*
             * RFC 5246 4.7. Note that earlier versions of TLS used a different RSA signature scheme
             * that did not include a DigestInfo encoding.
             */
                signer.update(hash, 0, hash.length);
            }

            return signer.verify(signedParams.getSignature());
        }
        catch (GeneralSecurityException e)
        {
            throw new IllegalStateException("unable to process signature: " + e.getMessage(), e);
        }
    }
}
