using NUnit.Framework;
using System;
using System.Linq;
using System.Security.Cryptography;

namespace CryptoUtils.Test
{
    [TestFixture]
    public class TestPem
    {
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

        private const string EccPublicKey =
            @"-----BEGIN PUBLIC KEY-----
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAACGNU1rVGpVfFyfPlx4Ydz0pQ0N
            2BCrIQpSccUmJbg6v1WYfYZNR9RAQuaONRAla0dhLC6NZ7oslIEW8iNdjA==
            -----END PUBLIC KEY-----";

        [Test]
        public void WhenKeyHasWrongHeader_ThenToRsaPublicKeyThrowsException()
        {
            Assert.Throws<FormatException>(
                () => Pem.FromRsaPublicKey(string.Empty));

            Assert.Throws<FormatException>(
                () => Pem.FromRsaPublicKey(EccPublicKey));
        }

        [Test]
        public void WhenKeyValid_ThenToRsaPublicKeyReturnsKey()
        {
            var key = Pem.FromRsaPublicKey(RsaPublicKey);
            Assert.IsNotNull(key);
        }

        [Test]
        public void WhenExportingAndImportingCngRsaKey_ThenKeyIsSame()
        {
            var key = new RSACng();
            var reimported = Pem.FromRsaPublicKey(key.ToRsaPublicKey());

            Assert.IsTrue(Enumerable.SequenceEqual(
                key.ExportParameters(false).Modulus,
                reimported.ExportParameters(false).Modulus));
            Assert.IsTrue(Enumerable.SequenceEqual(
                key.ExportParameters(false).Exponent,
                reimported.ExportParameters(false).Exponent));
        }

        [Test]
        public void WhenExportingAndImportingCryptoApiKey_ThenKeyIsSame()
        {
            var key = new RSACryptoServiceProvider();
            var reimported = Pem.FromRsaPublicKey(key.ToRsaPublicKey());

            Assert.IsTrue(Enumerable.SequenceEqual(
                key.ExportParameters(false).Modulus,
                reimported.ExportParameters(false).Modulus));
            Assert.IsTrue(Enumerable.SequenceEqual(
                key.ExportParameters(false).Exponent,
                reimported.ExportParameters(false).Exponent));
        }
    }
}
