using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace CryptoUtils
{
    /// <summary>
    /// Utility class to read and write RSA public key PEM files.
    /// </summary>
    public class RsaPublicKeyPem
    {
        private const string PemHeader = "-----BEGIN RSA PUBLIC KEY-----";
        private const string PemFooter = "-----END RSA PUBLIC KEY-----";

        private readonly string pem;

        public RsaPublicKeyPem(string pem)
        {
            if (pem == null || !pem.StartsWith(PemHeader))
            {
                throw new FormatException("Missing RSA Public key header");
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
            var keyBlob = CryptoApi.RsaPublicKeyBlobFromDer(
                derBlob,
                UnsafeNativeMethods.RSA_CSP_PUBLICKEYBLOB);

            return new RSACng(CngKey.Import(
                keyBlob,
                CngKeyBlobFormat.GenericPublicBlob));
#else
            var key = new RSACng();
            key.ImportRSAPublicKey(derBlob, out var _);
            return key;
#endif
        }

        /// <summary>
        /// Create RSA public key PEM for a given CNG or CryptoAPI key.
        /// </summary>
        public static RsaPublicKeyPem FromKey(RSA key)
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
                    UnsafeNativeMethods.CNG_RSA_PUBLIC_KEY_BLOB);
            }
            else if (key is RSACryptoServiceProvider cryptoApiKey)
            {
                var keyBlob = cryptoApiKey.ExportCspBlob(false);
                derBlob = CryptoApi.DerFromRsaPublicKeyBlob(
                    keyBlob,
                    UnsafeNativeMethods.RSA_CSP_PUBLICKEYBLOB);
            }
            else
            {
                throw new NotSupportedException("Unrecognized key type");
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

            return new RsaPublicKeyPem(buffer.ToString());
        }

        /// <summary>
        /// Load RSA public key PEM from file.
        /// </summary>
        public static RsaPublicKeyPem FromFile(string path)
        {
            return new RsaPublicKeyPem(File.ReadAllText(path, Encoding.ASCII));
        }
    }
}
