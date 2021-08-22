using System;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace CryptoUtils
{
    public class RSAPublicKey
    {
        private const string PemHeader = "-----BEGIN RSA PUBLIC KEY-----";
        private const string PemFooter = "-----END RSA PUBLIC KEY-----";

        private readonly string pem;

        public RSAPublicKey(string pem)
        {
            if (!pem.StartsWith(PemHeader))
            {
                throw new FormatException("Missing RSA Public key header");
            }

            this.pem = pem;
        }

        public override string ToString() => this.pem;

        /// <summary>
        /// Import a public key from a RSAPublicKey PEM file.
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

#if NET40_OR_GREATER

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
                    UnsafeNativeMethods.RSA_CSP_PUBLICKEYBLOB,
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
                        UnsafeNativeMethods.RSA_CSP_PUBLICKEYBLOB,
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

                    //
                    // Import the key blob.
                    //
                    var keyBlobBytes = new byte[keyBlobSize];
                    Marshal.Copy(keyBlob, keyBlobBytes, 0, (int)keyBlobSize);
                    return new RSACng(CngKey.Import(keyBlobBytes, CngKeyBlobFormat.GenericPublicBlob));
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
#else

            //
            // Import key.
            //
            var key = new RSACng();
            key.ImportRSAPublicKey(derBlob, out var _);
            return key;
#endif
        }

        /// <summary>
        /// Export a public key as RSAPublicKey PEM file.
        /// </summary>
        public static RSAPublicKey FromKey(RSA key)
        {
            byte[] derBlob;

#if NET40_OR_GREATER
            byte[] keyBlob;
            uint keyBlobType;

            //
            // CNG and CryptoAPI use different key blob formats, and expose
            // different APIs to create them.
            //
            if (key is RSACng cngKey)
            {
                keyBlob = cngKey.Key.Export(CngKeyBlobFormat.GenericPublicBlob);
                keyBlobType = UnsafeNativeMethods.CNG_RSA_PUBLIC_KEY_BLOB;
            }
            else if (key is RSACryptoServiceProvider cryptoApiKey)
            {
                keyBlob = cryptoApiKey.ExportCspBlob(false);
                keyBlobType = UnsafeNativeMethods.RSA_CSP_PUBLICKEYBLOB;
            }
            else
            {
                throw new NotSupportedException("Unrecognized key type");
            }

            //
            // Encode the key blob into DER.
            //
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

                derBlob = new byte[derBlobSize];
                Marshal.Copy(derBlobNative, derBlob, 0, (int)derBlobSize);
            }
            finally
            {
                Marshal.FreeHGlobal(derBlobNative);
            }

#else
            //
            // Export key as DER-formatted blob.
            //
            derBlob = key.ExportRSAPublicKey();
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

            return new RSAPublicKey(buffer.ToString());
        }
    }
}
