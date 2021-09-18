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
            var derBlob = Convert.FromBase64String(string.Concat(pem
                .Split('\n')
                .Select(s => s.Trim())
                .Where(line => !line.StartsWith("-----"))));

            //
            // Import key.
            //
#if NET40_OR_GREATER

            using (var derBlobNative = LocalAllocHandle.Alloc(derBlob.Length))
            {
                Marshal.Copy(
                    derBlob,
                    0,
                    derBlobNative.DangerousGetHandle(),
                    derBlob.Length);

                //
                // Decode DER blob into a CERT_PUBLIC_KEY_INFO.
                //

                if (UnsafeNativeMethods.CryptDecodeObjectEx(
                    UnsafeNativeMethods.X509_ASN_ENCODING |
                        UnsafeNativeMethods.PKCS_7_ASN_ENCODING,
                    UnsafeNativeMethods.X509_PUBLIC_KEY_INFO,
                    derBlobNative.DangerousGetHandle(),
                    (uint)derBlob.Length,
                    UnsafeNativeMethods.CRYPT_DECODE_ALLOC_FLAG,
                    IntPtr.Zero,
                    out var certInfoHandle,
                    out var certInfoSize))
                {
                    using (certInfoHandle)
                    {
                        //
                        // Check that the CERT_PUBLIC_KEY_INFO contains an RSA public key.
                        //
                        var certInfo = Marshal.PtrToStructure<UnsafeNativeMethods.CERT_PUBLIC_KEY_INFO>(
                            certInfoHandle.DangerousGetHandle());

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
            key.ImportSubjectPublicKeyInfo(derBlob, out var _);
            return key;
#endif
        }

        /// <summary>
        /// Create RSA public key PEM for a given CNG or CryptoAPI key.
        /// </summary>
        public static X509PublicKeyPem FromKey(RSA key)
        {
            byte[] derBlob;

#if NET40_OR_GREATER
            //
            // CNG and CryptoAPI use different key blob formats, and expose
            // different APIs to create them.
            //
            if (key is RSACng cngKey)
            {
                var keyBlob = cngKey.Key.Export(CngKeyBlobFormat.GenericPublicBlob);
                derBlob = CryptoApi.DerFromRsaPublicKeyBlob(
                    keyBlob,
                    UnsafeNativeMethods.X509_PUBLIC_KEY_INFO);
            }
            else if (key is RSACryptoServiceProvider cryptoApiKey)
            {
                var keyBlob = cryptoApiKey.ExportCspBlob(false);
                derBlob = CryptoApi.DerFromRsaPublicKeyBlob(
                    keyBlob,
                    UnsafeNativeMethods.X509_PUBLIC_KEY_INFO);
            }
            else
            {
                throw new NotSupportedException("Unrecognized key type");
            }
#else
            //
            // Export key as DER-formatted blob.
            //
            derBlob = key.ExportSubjectPublicKeyInfo();
#endif

            //
            // Wrap DER-formatted blob as PEM.
            //
            var buffer = new StringBuilder();
            buffer.AppendLine(PemHeader);
            buffer.AppendLine(Convert.ToBase64String(
                derBlob,
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
