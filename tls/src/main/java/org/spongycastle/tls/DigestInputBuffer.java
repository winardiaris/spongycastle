package org.spongycastle.tls;

import java.io.ByteArrayOutputStream;

import org.spongycastle.tls.crypto.TlsHash;

class DigestInputBuffer extends ByteArrayOutputStream
{
    void updateDigest(TlsHash d)
    {
        d.update(this.buf, 0, count);
    }
}
