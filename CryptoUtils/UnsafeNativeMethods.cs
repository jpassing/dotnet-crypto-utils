using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace CryptoUtils
{
    internal class UnsafeNativeMethods
    {
        //[DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        //[return: MarshalAs(UnmanagedType.Bool)]
        //internal static extern bool CryptStringToBinary(
        //    [MarshalAs(UnmanagedType.LPWStr)] string pszString, 
        //    uint cchString, 
        //    uint dwFlags, 
        //    IntPtr pbBinary, 
        //    ref uint pcbBinary, 
        //    out uint pdwSkip, 
        //    out uint pdwFlags);


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

        //internal delegate IntPtr CryptAlloc(IntPtr size);
        //internal delegate void CryptFree(IntPtr ptr);

        //[StructLayout(LayoutKind.Sequential)]
        //internal class CRYPT_DECODE_PARA
        //{
        //    uint cbSize;
        //    CryptAlloc pfnAlloc;
        //    CryptFree pfnFree;
        //}

        public const uint X509_ASN_ENCODING = 0x1;
        public const uint PKCS_7_ASN_ENCODING = 0x10000;

        //public const uint CRYPT_STRING_BASE64HEADER = 0;
        //public const uint CRYPT_STRING_BASE64 = 1;
        //public const uint CRYPT_STRING_BINARY = 2;
        //public const uint CRYPT_STRING_BASE64REQUESTHEADER = 3;
        //public const uint CRYPT_STRING_HEX = 4;
        //public const uint CRYPT_STRING_HEXASCII = 5;
        //public const uint CRYPT_STRING_BASE64_ANY = 6;
        //public const uint CRYPT_STRING_ANY = 7;
        //public const uint CRYPT_STRING_HEX_ANY = 8;
        //public const uint CRYPT_STRING_BASE64X509CRLHEADER = 9;
        //public const uint CRYPT_STRING_HEXADDR = 10;
        //public const uint CRYPT_STRING_HEXASCIIADDR = 11;
        //public const uint CRYPT_STRING_HEXRAW = 12;
        //public const uint CRYPT_STRING_NOCRLF = 0x40000000;
        //public const uint CRYPT_STRING_NOCR = 0x80000000;

        public const uint RSA_CSP_PUBLICKEYBLOB = 19;
        public const uint CNG_RSA_PUBLIC_KEY_BLOB = 72;
    }
}
