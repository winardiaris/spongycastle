package org.spongycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.spongycastle.crypto.CryptoException;
import org.spongycastle.crypto.DSA;
import org.spongycastle.crypto.Signer;
import org.spongycastle.crypto.digests.NullDigest;
import org.spongycastle.crypto.params.AsymmetricKeyParameter;
import org.spongycastle.crypto.params.ParametersWithRandom;
import org.spongycastle.crypto.signers.DSADigestSigner;
import org.spongycastle.tls.AlertDescription;
import org.spongycastle.tls.HashAlgorithm;
import org.spongycastle.tls.SignatureAndHashAlgorithm;
import org.spongycastle.tls.TlsFatalAlert;
import org.spongycastle.tls.crypto.TlsSigner;

/**
 * BC light-weight base class for the signers implementing the two DSA style algorithms from FIPS PUB 186-4: DSA and ECDSA.
 */
public abstract class BcTlsDSSSigner
    implements TlsSigner
{
    private final AsymmetricKeyParameter privateKey;
    private final BcTlsCrypto crypto;

    protected BcTlsDSSSigner(BcTlsCrypto crypto, AsymmetricKeyParameter privateKey)
    {
        this.crypto = crypto;

        if (privateKey == null)
        {
            throw new IllegalArgumentException("'privateKey' cannot be null");
        }
        if (!privateKey.isPrivate())
        {
            throw new IllegalArgumentException("'privateKey' must be private");
        }

        this.privateKey = privateKey;
    }

    protected abstract DSA createDSAImpl(short hashAlgorithm);

    protected abstract short getSignatureAlgorithm();

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm,
                                       byte[] hash) throws IOException
    {
        if (algorithm != null && algorithm.getSignature() != getSignatureAlgorithm())
        {
            throw new IllegalStateException();
        }
        
        short hashAlgorithm = algorithm == null ? HashAlgorithm.sha1 : algorithm.getHash();
        
        Signer s = new DSADigestSigner(createDSAImpl(hashAlgorithm), new NullDigest());
        s.init(true, new ParametersWithRandom(privateKey, crypto.getSecureRandom()));
        Signer signer = s;
        if (algorithm == null)
        {
            // Note: Only use the SHA1 part of the (MD5/SHA1) hash
            signer.update(hash, 16, 20);
        }
        else
        {
            signer.update(hash, 0, hash.length);
        }
        try
        {
            return signer.generateSignature();
        }
        catch (CryptoException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }
}
