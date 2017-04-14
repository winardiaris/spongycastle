package org.spongycastle.tls;

import java.io.IOException;

import org.spongycastle.tls.crypto.TlsCryptoParameters;
import org.spongycastle.tls.crypto.TlsSecret;

public interface TlsCredentialedDecryptor
    extends TlsCredentials
{
    TlsSecret decrypt(TlsCryptoParameters cryptoParams, byte[] ciphertext) throws IOException;
}
