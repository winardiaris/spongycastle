package org.spongycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;

import org.spongycastle.asn1.DERNull;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.DigestInfo;
import org.spongycastle.tls.AlertDescription;
import org.spongycastle.tls.SignatureAlgorithm;
import org.spongycastle.tls.SignatureAndHashAlgorithm;
import org.spongycastle.tls.TlsFatalAlert;
import org.spongycastle.tls.TlsUtils;
import org.spongycastle.tls.crypto.TlsSigner;

/**
 * Operator supporting the generation of RSA signatures.
 */
public class JcaTlsRSASigner
    implements TlsSigner
{
    private final PrivateKey privateKey;
    private final JcaTlsCrypto crypto;

    public JcaTlsRSASigner(JcaTlsCrypto crypto, PrivateKey privateKey)
    {
        this.crypto = crypto;

        if (privateKey == null)
        {
            throw new IllegalArgumentException("'privateKey' cannot be null");
        }

        this.privateKey = privateKey;
    }

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm,
                                       byte[] hash) throws IOException
    {
        try
        {
            Signature signer = crypto.getHelper().createSignature("NoneWithRSA");
            signer.initSign(privateKey, crypto.getSecureRandom());
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
                    throw new TlsFatalAlert(AlertDescription.internal_error, e);
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

            return signer.sign();
        }
        catch (GeneralSecurityException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }
}
