package org.spongycastle.tls.test;

import java.io.IOException;

import org.spongycastle.tls.DTLSClientProtocol;
import org.spongycastle.tls.DigitallySigned;

class DTLSTestClientProtocol extends DTLSClientProtocol
{
    protected final TlsTestConfig config;

    public DTLSTestClientProtocol(TlsTestConfig config)
    {
        super();

        this.config = config;
    }

    protected byte[] generateCertificateVerify(ClientHandshakeState state, DigitallySigned certificateVerify)
        throws IOException
    {
        if (certificateVerify.getAlgorithm() != null && config.clientAuthSigAlgClaimed != null)
        {
            certificateVerify = new DigitallySigned(config.clientAuthSigAlgClaimed, certificateVerify.getSignature());
        }

        return super.generateCertificateVerify(state, certificateVerify);
    }
}
