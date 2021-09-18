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
            using (var derBlobNative = LocalAllocHandle.Alloc(derBlob.Length))
            {
                Marshal.Copy(
                    derBlob,
                    0,
                    derBlobNative.DangerousGetHandle(),
                    derBlob.Length);

                //
                // Decode the key.
                //

                if (UnsafeNativeMethods.CryptDecodeObjectEx(
                    UnsafeNativeMethods.X509_ASN_ENCODING |
                        UnsafeNativeMethods.PKCS_7_ASN_ENCODING,
                    keyBlobType,
                    derBlobNative.DangerousGetHandle(),
                    (uint)derBlob.Length,
                    UnsafeNativeMethods.CRYPT_DECODE_ALLOC_FLAG,
                    IntPtr.Zero,
                    out var keyBlob,
                    out var keyBlobSize))
                {
                    using (keyBlob)
                    {
                        var keyBlobBytes = new byte[keyBlobSize];
                        Marshal.Copy(
                            keyBlob.DangerousGetHandle(),
                            keyBlobBytes,
                            0,
                            (int)keyBlobSize);

                        return keyBlobBytes;
                    }
                }
                else
                {
                    throw new CryptographicException(
                        "Failed to calculate buffer size for decoding key blob",
                        new Win32Exception());
                }
            }
        }

        public static byte[] DerFromRsaPublicKeyBlob(
            byte[] keyBlob,
            uint keyBlobType)
        {
            using (var keyBlobNative = LocalAllocHandle.Alloc(keyBlob.Length))
            {
                Marshal.Copy(
                    keyBlob, 
                    0, 
                    keyBlobNative.DangerousGetHandle(), 
                    keyBlob.Length);

                if (UnsafeNativeMethods.CryptEncodeObjectEx(
                    UnsafeNativeMethods.X509_ASN_ENCODING |
                        UnsafeNativeMethods.PKCS_7_ASN_ENCODING,
                    keyBlobType,
                    keyBlobNative.DangerousGetHandle(),
                    UnsafeNativeMethods.CRYPT_DECODE_ALLOC_FLAG,
                    IntPtr.Zero,
                    out var derBlobNative,
                    out uint derBlobSize))
                {
                    using (derBlobNative)
                    {
                        var derBlob = new byte[derBlobSize];
                        Marshal.Copy(
                            derBlobNative.DangerousGetHandle(),
                            derBlob,
                            0,
                            (int)derBlobSize);
                        return derBlob;
                    }
                }
                else
                {
                    throw new CryptographicException(
                        "Failed to calculate buffer size for encoding key blob",
                        new Win32Exception());
                }
            }
        }
    }
#endif
}
