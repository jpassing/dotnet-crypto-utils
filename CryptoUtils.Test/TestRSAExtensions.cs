using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace CryptoUtils.Test
{

    public abstract class TestRSAExtensions
    {
        private const string RsaPublicKeyPem =
            @"-----BEGIN RSA PUBLIC KEY-----
            MIIBigKCAYEAq3DnhgYgLVJknvDA3clATozPtjI7yauqD4/ZuqgZn4KzzzkQ4BzJ
            ar4jRygpzbghlFn0Luk1mdVKzPUgYj0VkbRlHyYfcahbgOHixOOnXkKXrtZW7yWG
            jXPqy/ZJ/+kFBNPAzxy7fDuAzKfU3Rn50sBakg95pua14W1oE4rtd4/U+sg2maCq
            6HgGdCLLxRWwXA8IBtvHZ48i6kxiz9tucFdS/ULvWsXjQnyE5rgs3tPhptyl2/js
            /6FGgdKDaPal8/tud/rPxYSuzBPp7YwRKRRN1EpYQdd4tZzeXdvOvrSIfH+ZL7Rc
            i+HGasbRjCom3HJL+wDGVggUkeuOUzZDjKGqZNCvZIqe5FuU0NAd8c2w2Mxaxia9
            1G8jZDu92DqCEI/HoxXsZPSjd0L4EMx5HqXpYpFY2YPL95zabmynO3RCTWFN7uq6
            DJGlzRCTHeRDa4CvNwHCzv0kqR4uo6VlWp2dW2M/v0k1+kP70EwGqq9dnK5RMXC3
            XwJbrAbpGUDlAgMBAAE=
            -----END RSA PUBLIC KEY-----";


        private const string SubjectPublicKeyInfoPem =
            @"-----BEGIN PUBLIC KEY-----
            MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAyItKCYN/yAzDEv2HaDaq
            kK3J5AjerXmP1ZhBa8r5M5xQTkHPnkOkOc1KPly/xH4hmBVf00dfGZ91hTez1iD0
            XKkmfwP4TGXZ1YeqvlS44bvt3yZCR09aA0cGwS5Dp6xFIlz3aahMaV3gXwqaNLxW
            Xy5qJSZLIXhxAd0uqlnudweoMgxMbmq8vSMGmx8U8r3x2ldYhdcDYD+wAJCDGPeI
            vNTcHmFujYH8cMobFjewQcGDtf2lOtHn6Q15h6cuENpI5q6Rl7Xmim+Xq6fwiAf7
            ivRRgtOTncBgBVPhjB6vmtSP1CbF6Mpww/ZPTuavBr3dCKmywBRiVHbndOZWREnB
            gdY3koteVKcIVWwzLwzjPJOX1jTWGdCkX/vs6qFOgfnFOd0mDEywF+AwBAXXADw4
            GxZllq/lzBNf6JWNLsHLQY19ke8doCkc4/C2Gn7+xJKqM/YVWEZxVR+WhqkDCpJV
            wtUlPtOf2x3nNM/kM8p8pZKDU6SWNlbuRgYH2GJa8ZPrAgMBAAE=
            -----END PUBLIC KEY-----";

        private const string EccPublicKeyPem =
            @"-----BEGIN PUBLIC KEY-----
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAACGNU1rVGpVfFyfPlx4Ydz0pQ0N
            2BCrIQpSccUmJbg6v1WYfYZNR9RAQuaONRAla0dhLC6NZ7oslIEW8iNdjA==
            -----END PUBLIC KEY-----";

        protected abstract RSA CreateKey();

        private static void AssertKeysEqual(RSA expected, RSA actual)
        {
            Assert.IsTrue(Enumerable.SequenceEqual(
                expected.ExportParameters(false).Modulus,
                actual.ExportParameters(false).Modulus));
            Assert.IsTrue(Enumerable.SequenceEqual(
                expected.ExportParameters(false).Exponent,
                actual.ExportParameters(false).Exponent));
        }

        private static void AssertPemEqual(string expected, string actual)
        {
            var expectedLines = expected.Split('\n');
            var actualLines = expected.Split('\n');

            Assert.AreEqual(expectedLines.First(), actualLines.First());
            Assert.AreEqual(expectedLines.Last(), actualLines.Last());

            var expectedBody = string.Concat(expectedLines
                .Where(line => !line.StartsWith("-----"))
                .Select(line => line.Trim()));
            var actualBody = string.Concat(actualLines
                .Where(line => !line.StartsWith("-----"))
                .Select(line => line.Trim()));

            Assert.AreEqual(expectedBody, actualBody);
        }

        [Test]
        public void WhenKeyValid_ThenExportSubjectPublicKeyInfoReturnsDerBlob()
        {
            var originalKey = CreateKey();
            var subjectPublicKeyInfoDer = originalKey.ExportSubjectPublicKeyInfo();

            var reimportedKey = CreateKey();
            reimportedKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfoDer, out var _);

            AssertKeysEqual(originalKey, reimportedKey);
        }

        [Test]
        public void WhenKeyValid_ThenExportRSAPublicKeyReturnsDerBlob()
        {
            var originalKey = CreateKey();
            var rsaPublicKeyDer = originalKey.ExportRSAPublicKey();

            var reimportedKey = CreateKey();
            reimportedKey.ImportRSAPublicKey(rsaPublicKeyDer, out var _);

            AssertKeysEqual(originalKey, reimportedKey);
        }

        [Test]
        public void WhenDerIsRSAPublicKey_ThenImportSubjectPublicKeyInfoThrowsException()
        {
            var originalKey = CreateKey();
            var rsaPublicKeyDer = originalKey.ExportRSAPublicKey();

            var reimportedKey = CreateKey();
            Assert.Throws<CryptographicException>(
                () => reimportedKey.ImportSubjectPublicKeyInfo(rsaPublicKeyDer, out var _));
        }

        [Test]
        public void WhenDerIsSubjectPublicKeyInfo_ThenImportSubjectPublicKeyInfoThrowsException()
        {
            var originalKey = CreateKey();
            var subjectPublicKeyInfoDer = originalKey.ExportSubjectPublicKeyInfo();

            var reimportedKey = CreateKey();
            Assert.Throws<CryptographicException>(
                () => reimportedKey.ImportRSAPublicKey(subjectPublicKeyInfoDer, out var _));
        }

        [Test]
        public void WhenPemContainsRSAPublicKey_ThenImportPublicKeySucceeds()
        {
            var importedKey = CreateKey();
            importedKey.ImportPublicKey(RsaPublicKeyPem, out var format);

            Assert.AreEqual(RsaPublicKeyFormat.RsaPublicKey, format);
            var exported = importedKey.ExportPublicKey(format);
            
            AssertPemEqual(RsaPublicKeyPem, exported);
        }

        [Test]
        public void WhenPemContainsSubjectPublicKeyInfo_ThenImportPublicKeySucceeds()
        {
            var importedKey = CreateKey();
            importedKey.ImportPublicKey(SubjectPublicKeyInfoPem, out var format);

            Assert.AreEqual(RsaPublicKeyFormat.SubjectPublicKeyInfo, format);
            var exported = importedKey.ExportPublicKey(format);

            AssertPemEqual(SubjectPublicKeyInfoPem, exported);
        }

        [Test]
        public void WhenPemContainsEccPublicKey_ThenImportPublicKeyThrowsException()
        {
            var importedKey = CreateKey();
            Assert.Throws<CryptographicException>(
                () => importedKey.ImportPublicKey(EccPublicKeyPem, out var format));
        }
    }

    [TestFixture]
    public class TestRSAExtensions_CNG : TestRSAExtensions
    {
        protected override RSA CreateKey() => new RSACng();
    }

    [TestFixture]
    public class TestRSAExtensions_CryptoServiceProvicer : TestRSAExtensions
    {
        protected override RSA CreateKey() => new RSACryptoServiceProvider();
    }
}
