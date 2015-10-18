package org.spongycastle.cms.jcajce;

import org.spongycastle.asn1.ASN1ObjectIdentifier;

interface KeyMaterialGenerator
{
    byte[] generateKDFMaterial(ASN1ObjectIdentifier keyAlgorithm, int keySize, byte[] userKeyMaterialParameters);
}
