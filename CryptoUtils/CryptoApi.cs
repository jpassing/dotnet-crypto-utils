﻿using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace CryptoUtils
{
#if NET40_OR_GREATER
    internal static class CryptoApi
    {
        public static byte[] RsaPublicKeyBlobFromDer(
            byte[] derBlob,
            uint keyBlobType)
        {
            var derBlobNative = Marshal.AllocHGlobal(derBlob.Length);
            Marshal.Copy(derBlob, 0, derBlobNative, derBlob.Length);

            try
            {
                //
                // Decode the key.
                //
                if (!UnsafeNativeMethods.CryptDecodeObjectEx(
                    UnsafeNativeMethods.X509_ASN_ENCODING |
                        UnsafeNativeMethods.PKCS_7_ASN_ENCODING,
                    keyBlobType,
                    derBlobNative,
                    (uint)derBlob.Length,
                    0,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    out var keyBlobSize))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "Failed to extract RSA public key blob");
                }

                var keyBlob = Marshal.AllocHGlobal((int)keyBlobSize);
                try
                {
                    if (!UnsafeNativeMethods.CryptDecodeObjectEx(
                        UnsafeNativeMethods.X509_ASN_ENCODING |
                            UnsafeNativeMethods.PKCS_7_ASN_ENCODING,
                        keyBlobType,
                        derBlobNative,
                        (uint)derBlob.Length,
                        0,
                        IntPtr.Zero,
                        keyBlob,
                        out keyBlobSize))
                    {
                        throw new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            "Failed to extract RSA public key blob");
                    }

                    var keyBlobBytes = new byte[keyBlobSize];
                    Marshal.Copy(keyBlob, keyBlobBytes, 0, (int)keyBlobSize);

                    return keyBlobBytes;
                }
                finally
                {
                    Marshal.FreeHGlobal(keyBlob);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(derBlobNative);
            }
        }

        public static byte[] DerFromRsaPublicKeyBlob(
            byte[] keyBlob,
            uint keyBlobType)
        {
            var keyBlobNative = Marshal.AllocHGlobal(keyBlob.Length);
            Marshal.Copy(keyBlob, 0, keyBlobNative, keyBlob.Length);

            if (!UnsafeNativeMethods.CryptEncodeObjectEx(
                UnsafeNativeMethods.X509_ASN_ENCODING |
                    UnsafeNativeMethods.PKCS_7_ASN_ENCODING,
                keyBlobType,
                keyBlobNative,
                0,
                IntPtr.Zero,
                IntPtr.Zero,
                out uint derBlobSize))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Failed to encode RSA public key blob");
            }

            var derBlobNative = Marshal.AllocHGlobal((int)derBlobSize);
            try
            {
                if (!UnsafeNativeMethods.CryptEncodeObjectEx(
                    UnsafeNativeMethods.X509_ASN_ENCODING |
                        UnsafeNativeMethods.PKCS_7_ASN_ENCODING,
                    keyBlobType,
                    keyBlobNative,
                    0,
                    IntPtr.Zero,
                    derBlobNative,
                    out derBlobSize))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "Failed to encode RSA public key blob");
                }

                var derBlob = new byte[derBlobSize];
                Marshal.Copy(derBlobNative, derBlob, 0, (int)derBlobSize);
                return derBlob;
            }
            finally
            {
                Marshal.FreeHGlobal(derBlobNative);
            }
        }
    }
#endif
}
