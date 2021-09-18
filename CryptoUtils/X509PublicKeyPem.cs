using System;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace CryptoUtils
{
    /// <summary>
    /// Utility class to read and write RSA public key PEM files.
    /// </summary>
    public class X509PublicKeyPem
    {
        private const string RsaOid = "1.2.840.113549.1.1.1";
        private const string PemHeader = "-----BEGIN PUBLIC KEY-----";
        private const string PemFooter = "-----END PUBLIC KEY-----";

        private readonly string pem;

        public X509PublicKeyPem(string pem)
        {
            if (pem == null || !pem.StartsWith(PemHeader))
            {
                throw new FormatException("Missing Public key header");
            }

            this.pem = pem;
        }

        /// <summary>
        /// Return RSA public key PEM as string.
        /// </summary>
        /// <returns></returns>
        public override string ToString() => this.pem;

        /// <summary>
        /// Create CNG key from RSA public key PEM.
        /// </summary>
        public RSA ToKey()
        {
            //
            // Extract DER-formatted blob.
            //
            var certKeyInfoDer = Convert.FromBase64String(string.Concat(pem
                .Split('\n')
                .Select(s => s.Trim())
                .Where(line => !line.StartsWith("-----"))));

            //
            // Import key.
            //
#if NET40_OR_GREATER

            using (var certKeyInfoDerHandle = LocalAllocHandle.Alloc(certKeyInfoDer.Length))
            {
                Marshal.Copy(
                    certKeyInfoDer,
                    0,
                    certKeyInfoDerHandle.DangerousGetHandle(),
                    certKeyInfoDer.Length);

                //
                // Decode DER blob into a CERT_PUBLIC_KEY_INFO.
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
                        // Decode the RSA public key.
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

                                return new RSACng(CngKey.Import(
                                    keyBlobBytes,
                                    CngKeyBlobFormat.GenericPublicBlob));
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
#else
            var key = new RSACng();
            key.ImportSubjectPublicKeyInfo(certKeyInfoDer, out var _);
            return key;
#endif
        }

        /// <summary>
        /// Create RSA public key PEM for a given CNG or CryptoAPI key.
        /// </summary>
        public static X509PublicKeyPem FromKey(RSA key)
        {
            byte[] certKeyInfoDer;

#if NET40_OR_GREATER
            //
            // CNG and CryptoAPI use different key blob formats, and expose
            // different APIs to create them.
            //
            byte[] cspBlob;
            uint cspBlobType;
            if (key is RSACng cngKey)
            {
                cspBlob = cngKey.Key.Export(CngKeyBlobFormat.GenericPublicBlob);
                cspBlobType = UnsafeNativeMethods.CNG_RSA_PUBLIC_KEY_BLOB;
            }
            else if (key is RSACryptoServiceProvider cryptoApiKey)
            {
                cspBlob = cryptoApiKey.ExportCspBlob(false);
                cspBlobType = UnsafeNativeMethods.RSA_CSP_PUBLICKEYBLOB;
            }
            else
            {
                throw new NotSupportedException("Unrecognized key type");
            }

            //
            // Decode CSP blob into DER.
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
                        // Wrap the DER blob into a CERT_PUBLIC_KEY_INFO.
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

                        using (var certKeyInfoHandle = LocalAllocHandle.Alloc(Marshal.SizeOf<UnsafeNativeMethods.CERT_PUBLIC_KEY_INFO>()))
                        {
                            Marshal.StructureToPtr(certKeyInfo, certKeyInfoHandle.DangerousGetHandle(), false);

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
                                    certKeyInfoDer = new byte[certKeyInfoDerSize];
                                    Marshal.Copy(
                                        certKeyInfoDerHandle.DangerousGetHandle(),
                                        certKeyInfoDer,
                                        0,
                                        (int)certKeyInfoDerSize);
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


#else
            //
            // Export key as DER-formatted blob.
            //
            certKeyInfoDer = key.ExportSubjectPublicKeyInfo();
#endif

            //
            // Wrap DER-formatted blob as PEM.
            //
            var buffer = new StringBuilder();
            buffer.AppendLine(PemHeader);
            buffer.AppendLine(Convert.ToBase64String(
                certKeyInfoDer,
                Base64FormattingOptions.InsertLineBreaks));
            buffer.AppendLine(PemFooter);

            return new X509PublicKeyPem(buffer.ToString());
        }

        /// <summary>
        /// Load RSA public key PEM from file.
        /// </summary>
        public static X509PublicKeyPem FromFile(string path)
        {
            return new X509PublicKeyPem(File.ReadAllText(path, Encoding.ASCII));
        }
    }
}
