using NUnit.Framework;
using System;
using System.Linq;
using System.Security.Cryptography;

namespace CryptoUtils.Test
{
    [TestFixture]
    public class TestX509PublicKeyPem
    {
        private const string X509PublicKey =
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

        private const string RsaPublicKey =
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

        [Test]
        public void WhenKeyHasWrongHeader_ThenConstructorThrowsException()
        {
            Assert.Throws<FormatException>(
                () => new X509PublicKeyPem(string.Empty));

            Assert.Throws<FormatException>(
                () => new X509PublicKeyPem(RsaPublicKey));
        }

        [Test]
        public void WhenKeyValid_ThenToStringReturnsPem()
        {
            Assert.AreEqual(
                X509PublicKey,
                new X509PublicKeyPem(X509PublicKey).ToString());
        }

        [Test]
        public void WhenKeyValid_ThenToKeyReturnsKey()
        {
            var key = new X509PublicKeyPem(X509PublicKey).ToKey();
            Assert.IsNotNull(key);
        }

        [Test]
        public void WhenImportingAndExportingCngRsaKey_ThenKeyIsSame()
        {
            var key = new RSACng();
            var exported = X509PublicKeyPem.FromKey(key).ToString();
            var reimported = new X509PublicKeyPem(exported);

            Assert.AreEqual(exported, reimported.ToString());
            Assert.IsTrue(Enumerable.SequenceEqual(
                key.ExportParameters(false).Modulus,
                reimported.ToKey().ExportParameters(false).Modulus));
            Assert.IsTrue(Enumerable.SequenceEqual(
                key.ExportParameters(false).Exponent,
                reimported.ToKey().ExportParameters(false).Exponent));
        }

        [Test]
        public void WhenImportingAndExportingCryptoApiKey_ThenKeyIsSame()
        {
            var key = new RSACryptoServiceProvider();
            var exported = X509PublicKeyPem.FromKey(key).ToString();
            var reimported = new X509PublicKeyPem(exported);

            Assert.AreEqual(exported, reimported.ToString());
            Assert.IsTrue(Enumerable.SequenceEqual(
                key.ExportParameters(false).Modulus,
                reimported.ToKey().ExportParameters(false).Modulus));
            Assert.IsTrue(Enumerable.SequenceEqual(
                key.ExportParameters(false).Exponent,
                reimported.ToKey().ExportParameters(false).Exponent));
        }
    }
}
