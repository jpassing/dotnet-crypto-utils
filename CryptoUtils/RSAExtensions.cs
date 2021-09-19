//
// Copyright 2021 Johannes Passing, https://jpassing.com/
//
// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
// 
//   http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.   
// 

using System;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace CryptoUtils
{
    public static class RSAExtensions
    {
        private const string RsaPublickeyPemHeader = "-----BEGIN RSA PUBLIC KEY-----";
        private const string RsaPublickeyPemFooter = "-----END RSA PUBLIC KEY-----";
        private const string SubjectPublicKeyInfoPemHeader = "-----BEGIN PUBLIC KEY-----";
        private const string SubjectPublicKeyInfoPemFooter = "-----END PUBLIC KEY-----";

        private const string RsaOid = "1.2.840.113549.1.1.1";

        //---------------------------------------------------------------------
        // NetFx surrogate implementations for methods available in .NET Core/
        // .NET 5+.
        //---------------------------------------------------------------------

#if NET40_OR_GREATER

        private static void ImportCspBlob(
            RSA key,
            byte[] cspBlob)
        {
            if (key is RSACng)
            {
                //
                // RSACng.Key is private, so we can't import into
                // an existing key directly. But we can do so
                // indirectly.
                //
                var importedKey = CngKey.Import(cspBlob, CngKeyBlobFormat.GenericPublicBlob);
                var importedKeyParameters = new RSACng(importedKey).ExportParameters(false);
                key.ImportParameters(importedKeyParameters);
            }
            else if (key is RSACryptoServiceProvider cryptoApiKey)
            {
                cryptoApiKey.ImportCspBlob(cspBlob);
            }
            else
            {
                throw new ArgumentException("Unrecognized key type");
            }
        }

        private static byte[] ExportCspBlob(
            RSA key,
            out uint cspBlobType)
        {
            //
            // CNG and CryptoAPI use different key blob formats, and expose
            // different APIs to create them.
            //
            if (key is RSACng cngKey)
            {
                cspBlobType = UnsafeNativeMethods.CNG_RSA_PUBLIC_KEY_BLOB;
                return cngKey.Key.Export(CngKeyBlobFormat.GenericPublicBlob);
            }
            else if (key is RSACryptoServiceProvider cryptoApiKey)
            {
                cspBlobType = UnsafeNativeMethods.RSA_CSP_PUBLICKEYBLOB;
                return cryptoApiKey.ExportCspBlob(false);
            }
            else
            {
                throw new ArgumentException("Unrecognized key type");
            }
        }

        /// <summary>
        /// Exports the public-key portion of the current key in the X.509 
        /// SubjectPublicKeyInfo
        /// format.
        /// </summary>
        /// <returns>
        /// A byte array containing the X.509 SubjectPublicKeyInfo representation of the
        /// public-key portion of this key.
        /// </returns>
        public static byte[] ExportSubjectPublicKeyInfo(this RSA key)
        {
            byte[] cspBlob = ExportCspBlob(key, out uint cspBlobType);

            //
            // Decode CSP blob -> RSA PublicKey DER.
            //
            using (var cspBlobHandle = LocalAllocHandle.Alloc(cspBlob.Length))
            {
                Marshal.Copy(
                    cspBlob,
                    0,
                    cspBlobHandle.DangerousGetHandle(),
                    cspBlob.Length);

                if (UnsafeNativeMethods.CryptEncodeObjectEx(
                    UnsafeNativeMethods.X509_ASN_ENCODING |
                        UnsafeNativeMethods.PKCS_7_ASN_ENCODING,
                    cspBlobType,
                    cspBlobHandle.DangerousGetHandle(),
                    UnsafeNativeMethods.CRYPT_DECODE_ALLOC_FLAG,
                    IntPtr.Zero,
                    out var rsaDerHandle,
                    out uint rsaDerSize))
                {
                    using (rsaDerHandle)
                    {
                        //
                        // Wrap the RSA PublicKey DER blob into a CERT_PUBLIC_KEY_INFO.
                        //
                        var certKeyInfo = new UnsafeNativeMethods.CERT_PUBLIC_KEY_INFO()
                        {
                            Algorithm = new UnsafeNativeMethods.CRYPT_ALGORITHM_IDENTIFIER()
                            {
                                pszObjId = RsaOid
                            },
                            PublicKey = new UnsafeNativeMethods.CRYPT_BIT_BLOB()
                            {
                                pbData = rsaDerHandle.DangerousGetHandle(),
                                cbData = rsaDerSize
                            }
                        };

                        //
                        // Encode CERT_PUBLIC_KEY_INFO -> DER.
                        //
                        using (var certKeyInfoHandle = LocalAllocHandle.Alloc(
                            Marshal.SizeOf<UnsafeNativeMethods.CERT_PUBLIC_KEY_INFO>()))
                        {
                            Marshal.StructureToPtr(
                                certKeyInfo, 
                                certKeyInfoHandle.DangerousGetHandle(), 
                                false);

                            if (UnsafeNativeMethods.CryptEncodeObjectEx(
                                UnsafeNativeMethods.X509_ASN_ENCODING |
                                    UnsafeNativeMethods.PKCS_7_ASN_ENCODING,
                                UnsafeNativeMethods.X509_PUBLIC_KEY_INFO,
                                certKeyInfoHandle.DangerousGetHandle(),
                                UnsafeNativeMethods.CRYPT_DECODE_ALLOC_FLAG,
                                IntPtr.Zero,
                                out var certKeyInfoDerHandle,
                                out uint certKeyInfoDerSize))
                            {
                                using (certKeyInfoDerHandle)
                                {
                                    var certKeyInfoDer = new byte[certKeyInfoDerSize];
                                    Marshal.Copy(
                                        certKeyInfoDerHandle.DangerousGetHandle(),
                                        certKeyInfoDer,
                                        0,
                                        (int)certKeyInfoDerSize);
                                    return certKeyInfoDer;
                                }
                            }
                            else
                            {
                                throw new CryptographicException(
                                    "Failed to encode CERT_PUBLIC_KEY_INFO",
                                    new Win32Exception());
                            }
                        }
                    }
                }
                else
                {
                    throw new CryptographicException(
                        "Failed to encode CSP blob",
                        new Win32Exception());
                }
            }
        }

        /// <summary>
        /// Exports the public-key portion of the current key in the PKCS#1 RSAPublicKey
        /// format.
        /// </summary>
        /// <returns>
        /// A byte array containing the PKCS#1 RSAPublicKey representation of this key.
        /// </returns>
        public static byte[] ExportRSAPublicKey(this RSA key)
        {
            byte[] cspBlob = ExportCspBlob(key, out uint cspBlobType);

            //
            // Decode CSP blob -> RSA PublicKey DER.
            //
            using (var cspBlobHandle = LocalAllocHandle.Alloc(cspBlob.Length))
            {
                Marshal.Copy(
                    cspBlob,
                    0,
                    cspBlobHandle.DangerousGetHandle(),
                    cspBlob.Length);

                if (UnsafeNativeMethods.CryptEncodeObjectEx(
                    UnsafeNativeMethods.X509_ASN_ENCODING |
                        UnsafeNativeMethods.PKCS_7_ASN_ENCODING,
                    cspBlobType,
                    cspBlobHandle.DangerousGetHandle(),
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
                        "Failed to encode CSP blob",
                        new Win32Exception());
                }
            }
        }

        /// <summary>
        /// Imports the public key from a PKCS#1 RSAPublicKey structure after decryption,
        /// replacing the keys for this object.
        /// </summary>
        /// <param name="derBlob">
        /// The bytes of a PKCS#1 RSAPublicKey structure in the ASN.1-BER encoding.
        /// </param>
        /// <param name="bytesRead">
        /// When this method returns, contains a value that indicates the number of bytes
        /// read from source. This parameter is treated as uninitialized.
        /// </param>
        public static void ImportRSAPublicKey(
            this RSA key,
            byte[] derBlob, 
            out int bytesRead)
        {
            using (var derBlobHandle = LocalAllocHandle.Alloc(derBlob.Length))
            {
                Marshal.Copy(
                    derBlob,
                    0,
                    derBlobHandle.DangerousGetHandle(),
                    derBlob.Length);

                //
                // Decode RSA PublicKey DER -> CSP blob.
                //
                if (UnsafeNativeMethods.CryptDecodeObjectEx(
                    UnsafeNativeMethods.X509_ASN_ENCODING |
                        UnsafeNativeMethods.PKCS_7_ASN_ENCODING,
                    UnsafeNativeMethods.RSA_CSP_PUBLICKEYBLOB,
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

                        bytesRead = derBlob.Length;
                        ImportCspBlob(key, keyBlobBytes);
                    }
                }
                else
                {
                    throw new CryptographicException(
                        "Failed to decode DER blob",
                        new Win32Exception());
                }
            }
        }

        /// <summary>
        /// Imports the public key from an X.509 SubjectPublicKeyInfo structure 
        /// after decryption,
        /// replacing the keys for this object.
        /// </summary>
        /// <param name="certKeyInfoDer">
        /// The bytes of an X.509 SubjectPublicKeyInfo structure in the ASN.1-DER encoding.
        /// </param>
        /// <param name="bytesRead">
        /// When this method returns, contains a value that indicates the number of bytes
        /// read from source. This parameter is treated as uninitialized.
        /// </param>
        public static void ImportSubjectPublicKeyInfo(
            this RSA key,
            byte[] certKeyInfoDer, 
            out int bytesRead)

        {
            using (var certKeyInfoDerHandle = LocalAllocHandle.Alloc(certKeyInfoDer.Length))
            {
                Marshal.Copy(
                    certKeyInfoDer,
                    0,
                    certKeyInfoDerHandle.DangerousGetHandle(),
                    certKeyInfoDer.Length);

                //
                // Decode DER -> CERT_PUBLIC_KEY_INFO.
                //
                if (UnsafeNativeMethods.CryptDecodeObjectEx(
                    UnsafeNativeMethods.X509_ASN_ENCODING |
                        UnsafeNativeMethods.PKCS_7_ASN_ENCODING,
                    UnsafeNativeMethods.X509_PUBLIC_KEY_INFO,
                    certKeyInfoDerHandle.DangerousGetHandle(),
                    (uint)certKeyInfoDer.Length,
                    UnsafeNativeMethods.CRYPT_DECODE_ALLOC_FLAG,
                    IntPtr.Zero,
                    out var certKeyInfoHandle,
                    out var certKeyInfoSize))
                {
                    using (certKeyInfoHandle)
                    {
                        //
                        // Check that the CERT_PUBLIC_KEY_INFO contains an RSA public key.
                        //
                        var certInfo = Marshal.PtrToStructure<UnsafeNativeMethods.CERT_PUBLIC_KEY_INFO>(
                            certKeyInfoHandle.DangerousGetHandle());

                        if (certInfo.Algorithm.pszObjId != RsaOid)
                        {
                            throw new CryptographicException("Not an RSA public key");
                        }

                        //
                        // Decode the RSA public key -> CSP blob.
                        //
                        if (UnsafeNativeMethods.CryptDecodeObjectEx(
                            UnsafeNativeMethods.X509_ASN_ENCODING |
                                UnsafeNativeMethods.PKCS_7_ASN_ENCODING,
                            UnsafeNativeMethods.RSA_CSP_PUBLICKEYBLOB,
                            certInfo.PublicKey.pbData,
                            certInfo.PublicKey.cbData,
                            UnsafeNativeMethods.CRYPT_DECODE_ALLOC_FLAG,
                            IntPtr.Zero,
                            out var cspKeyBlob,
                            out var cspKeyBlobSize))
                        {
                            using (cspKeyBlob)
                            {
                                var keyBlobBytes = new byte[cspKeyBlobSize];
                                Marshal.Copy(
                                    cspKeyBlob.DangerousGetHandle(),
                                    keyBlobBytes,
                                    0,
                                    (int)cspKeyBlobSize);

                                bytesRead = certKeyInfoDer.Length;
                                ImportCspBlob(key, keyBlobBytes);
                            }
                        }
                        else
                        {
                            throw new CryptographicException(
                                "Failed to decode RSA public key from CERT_PUBLIC_KEY_INFO",
                                new Win32Exception());
                        }
                    }
                }
                else
                {
                    throw new CryptographicException(
                        "Failed to decode DER blob into CERT_PUBLIC_KEY_INFO",
                        new Win32Exception());
                }
            }
        }
#endif

        //---------------------------------------------------------------------
        // Convenience methods for reading/writing PEM-encoded keys.
        //---------------------------------------------------------------------

#if !(NET5_0 || NET5_0_OR_GREATER)
        public static void ImportFromPem(
            this RSA key,
            string source)
            => ImportFromPem(key, source, out var _);
#endif

        public static void ImportFromPem(
            this RSA key,
            string source,
            out RsaPublicKeyFormat format)
        {
            source = source.Trim();

            //
            // Inspect header to determine format.
            //
            if (source.StartsWith(SubjectPublicKeyInfoPemHeader) &&
                source.EndsWith(SubjectPublicKeyInfoPemFooter))
            {
                format = RsaPublicKeyFormat.SubjectPublicKeyInfo;
            }
            else if (source.StartsWith(RsaPublickeyPemHeader) &&
                     source.EndsWith(RsaPublickeyPemFooter))
            {
                format = RsaPublicKeyFormat.RsaPublicKey;
            }
            else
            {
                throw new FormatException("Missing Public key header/footer");
            }

            //
            // Decode body to get DER blob.
            //
            var der = Convert.FromBase64String(string.Concat(
                source
                    .Split('\n')
                    .Select(s => s.Trim())
                    .Where(line => !line.StartsWith("-----"))));
            if (format == RsaPublicKeyFormat.RsaPublicKey)
            {
                key.ImportRSAPublicKey(der, out var _);
            }
            else
            {
                key.ImportSubjectPublicKeyInfo(der, out var _);
            }
        }

        public static string ExportToPem(
            this RSA key,
            RsaPublicKeyFormat format)
        {
            var buffer = new StringBuilder();

            if (format == RsaPublicKeyFormat.RsaPublicKey)
            {
                buffer.AppendLine(RsaPublickeyPemHeader);
                buffer.AppendLine(Convert.ToBase64String(
                    key.ExportRSAPublicKey(),
                    Base64FormattingOptions.InsertLineBreaks));
                buffer.AppendLine(RsaPublickeyPemFooter);
            }
            else if (format == RsaPublicKeyFormat.SubjectPublicKeyInfo)
            {
                buffer.AppendLine(SubjectPublicKeyInfoPemHeader);
                buffer.AppendLine(Convert.ToBase64String(
                    key.ExportSubjectPublicKeyInfo(),
                    Base64FormattingOptions.InsertLineBreaks));
                buffer.AppendLine(SubjectPublicKeyInfoPemFooter);
            }
            else
            {
                throw new ArgumentException(nameof(format));
            }

            return buffer.ToString();
        }
    }

    public enum RsaPublicKeyFormat
    {
        /// <summary>
        /// -----BEGIN RSA PUBLIC KEY-----
        /// </summary>
        RsaPublicKey,

        /// <summary>
        /// -----BEGIN PUBLIC KEY-----
        /// </summary>
        SubjectPublicKeyInfo
    }
}
