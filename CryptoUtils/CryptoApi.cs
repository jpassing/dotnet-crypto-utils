using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;


// Resources:
// https://github.com/microsoft/Windows-universal-samples/blob/main/Samples/MicrosoftPassport/Server/Models/SubjectPublicKeyInfo.cs

namespace CryptoUtils
{
#if NET40_OR_GREATER
    internal static class CryptoApi
    {
        public static byte[] RsaPublicKeyBlobFromDer(
            byte[] derBlob,
            uint keyBlobType)
        {
            using (var derBlobHandle = LocalAllocHandle.Alloc(derBlob.Length))
            {
                Marshal.Copy(
                    derBlob,
                    0,
                    derBlobHandle.DangerousGetHandle(),
                    derBlob.Length);

                //
                // Decode the key.
                //

                if (UnsafeNativeMethods.CryptDecodeObjectEx(
                    UnsafeNativeMethods.X509_ASN_ENCODING |
                        UnsafeNativeMethods.PKCS_7_ASN_ENCODING,
                    keyBlobType,
                    derBlobHandle.DangerousGetHandle(),
                    (uint)derBlob.Length,
                    UnsafeNativeMethods.CRYPT_DECODE_ALLOC_FLAG,
                    IntPtr.Zero,
                    out var keyBlobHandle,
                    out var keyBlobSize))
                {
                    using (keyBlobHandle)
                    {
                        var keyBlobBytes = new byte[keyBlobSize];
                        Marshal.Copy(
                            keyBlobHandle.DangerousGetHandle(),
                            keyBlobBytes,
                            0,
                            (int)keyBlobSize);

                        return keyBlobBytes;
                    }
                }
                else
                {
                    throw new CryptographicException(
                        "Failed to decode key blob from DER",
                        new Win32Exception());
                }
            }
        }

        public static byte[] DerFromRsaPublicKeyBlob(
            byte[] keyBlob,
            uint keyBlobType)
        {
            using (var keyBlobHandle = LocalAllocHandle.Alloc(keyBlob.Length))
            {
                Marshal.Copy(
                    keyBlob, 
                    0, 
                    keyBlobHandle.DangerousGetHandle(), 
                    keyBlob.Length);

                if (UnsafeNativeMethods.CryptEncodeObjectEx(
                    UnsafeNativeMethods.X509_ASN_ENCODING |
                        UnsafeNativeMethods.PKCS_7_ASN_ENCODING,
                    keyBlobType,
                    keyBlobHandle.DangerousGetHandle(),
                    UnsafeNativeMethods.CRYPT_DECODE_ALLOC_FLAG,
                    IntPtr.Zero,
                    out var derBlobHandle,
                    out uint derBlobSize))
                {
                    using (derBlobHandle)
                    {
                        var derBlob = new byte[derBlobSize];
                        Marshal.Copy(
                            derBlobHandle.DangerousGetHandle(),
                            derBlob,
                            0,
                            (int)derBlobSize);
                        return derBlob;
                    }
                }
                else
                {
                    throw new CryptographicException(
                        "Failed to encode key blob into DER",
                        new Win32Exception());
                }
            }
        }
    }
#endif
}
