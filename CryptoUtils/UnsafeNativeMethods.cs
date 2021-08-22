using System;
using System.Runtime.InteropServices;

namespace CryptoUtils
{
    internal class UnsafeNativeMethods
    {
        [DllImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptDecodeObjectEx(
            uint dwCertEncodingType,
            uint lpszStructType,
            IntPtr pbEncoded,
            uint cbEncoded,
            uint dwFlags,
            IntPtr pDecodePara,
            IntPtr pvStructInfo,
            out uint pcbStructInfo);

        [DllImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptEncodeObjectEx(
            uint dwCertEncodingType,
            uint lpszStructType,
            IntPtr pvStructInfo,
            uint dwFlags,
            IntPtr pDecodePara,
            IntPtr pvEncoded,
            out uint pcbEncoded);

        public const uint X509_ASN_ENCODING = 0x1;
        public const uint PKCS_7_ASN_ENCODING = 0x10000;

        public const uint RSA_CSP_PUBLICKEYBLOB = 19;
        public const uint CNG_RSA_PUBLIC_KEY_BLOB = 72;
    }
}
