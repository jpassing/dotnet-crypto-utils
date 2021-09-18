﻿using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.ConstrainedExecution;
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
            out LocalAllocHandle pvStructInfo,
            out uint pcbStructInfo);

        [DllImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptEncodeObjectEx(
            uint dwCertEncodingType,
            uint lpszStructType,
            IntPtr pvStructInfo,
            uint dwFlags,
            IntPtr pDecodePara,
            out LocalAllocHandle pvEncoded,
            out uint pcbEncoded);

        public const uint X509_ASN_ENCODING = 0x1;
        public const uint PKCS_7_ASN_ENCODING = 0x10000;
        public const uint CRYPT_DECODE_ALLOC_FLAG = 0x8000;

        //
        // Constants for CryptEncodeObject and CryptDecodeObject.
        // 
        // https://docs.microsoft.com/en-us/windows/win32/seccrypto/constants-for-cryptencodeobject-and-cryptdecodeobject
        //
        public const uint X509_PUBLIC_KEY_INFO = 8;
        public const uint RSA_CSP_PUBLICKEYBLOB = 19;
        public const uint CNG_RSA_PUBLIC_KEY_BLOB = 72;
        
        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_ALGORITHM_IDENTIFIER
        {
            [MarshalAs(UnmanagedType.LPStr)] public string pszObjId;
            public int cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_BIT_BLOB
        {
            public uint cbData;
            public IntPtr pbData;
            public uint cUnusedBits;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CERT_PUBLIC_KEY_INFO
        {
            public CRYPT_ALGORITHM_IDENTIFIER Algorithm;
            public CRYPT_BIT_BLOB PublicKey;
        }
    }

    internal sealed class LocalAllocHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private LocalAllocHandle() : base(ownsHandle: true) { }

        public static LocalAllocHandle Alloc(int cb)
        {
            LocalAllocHandle handle = new LocalAllocHandle();
            handle.AllocCore(cb);
            return handle;
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        private void AllocCore(int cb)
        {
            SetHandle(Marshal.AllocHGlobal(cb));
        }

        protected override bool ReleaseHandle()
        {
            Marshal.FreeHGlobal(handle);
            return true;
        }
    }

}
