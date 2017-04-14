package org.spongycastle.tls;

import org.spongycastle.tls.crypto.TlsDHConfig;

public interface TlsDHConfigVerifier
{
    /**
     * Check whether the given DH configuration is acceptable for use.
     * 
     * @param dhConfig the {@link TlsDHConfig} to check
     * @return true if (and only if) the specified configuration is acceptable
     */
    boolean accept(TlsDHConfig dhConfig);
}
