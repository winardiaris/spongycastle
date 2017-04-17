package org.spongycastle.tls;

import java.io.OutputStream;

public interface TlsCompression
{
    OutputStream compress(OutputStream output);

    OutputStream decompress(OutputStream output);
}
