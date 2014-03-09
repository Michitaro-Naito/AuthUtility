using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using AuthUtility;
using System.Security.Cryptography;

namespace AuthUtilityTest
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void GamePassSignTest()
        {
            // Tests using generated keys
            string privateKeyXmlString;
            string publicKeyXmlString;
            using (var rsa = new RSACryptoServiceProvider())
            {
                privateKeyXmlString = rsa.ToXmlString(true);
                publicKeyXmlString = rsa.ToXmlString(false);
            }
            TestGamePass(privateKeyXmlString, publicKeyXmlString);

            // Tests using exported keys
            privateKeyXmlString = "<RSAKeyValue><Modulus>hhjhOYvcx6I2qwtLbE2k1wmYO3c46S7Ay7U4/3yaNgaNXXXSuzCux0y6vLq1ucu7sJISPklayGHqYPzOO9oDpe+MB44g1btuWyEzj162+JPI8caU3Wqu5IP9WVjayG9/nvEmCvB4TuoopoxLdX9GZvLvI2SdBfa3r0T9tuX4J2E=</Modulus><Exponent>AQAB</Exponent><P>tjfM5wE5ib73m+kSU9q44gjXG9GljoqS0mnAgZXNx0V3U5YG7Qf1e2oIFKL3v7MbiShDhKw2FcpOyDgyzTltLQ==</P><Q>vGUD14ZArvtGfuwSXCLstM2V0HskqZLeaMfsiImN/M68PELKHC2w6doOesqPzEqmJpJFtTPm4RV8BwLGsyeLhQ==</Q><DP>RaxyccXbHVtizD/DXULdvLgKoD16Y1WDLGd5T1Nbep2KMfDEty964vS5IELsHmW62qgFoR5EE/LmStKKQkR6BQ==</DP><DQ>C1FCLtNY1Wow7PT/kVtjvuTOyCxtomY5SDAibH1e8z30HuagP5sbEqFP116Nzub5Hj4RQ/ZvOzxQLBelmiOZBQ==</DQ><InverseQ>eQR2zzt/cFdFgwPvm5utAXrBGuX0ZrntjR4TuEv8UcNlQuPaLvDreze5qurZPkF+XFGaw7H829LCh/vn/rDjmw==</InverseQ><D>Eb2v6nuhCX5iCi4T2+/Hy7VWwSNMUblgQ3Ml59M12cjzIfbJGv/dV7vEhtyS11JncfxZUolE6/bcWdmIdW2qBrSKt28uxGcd6isiCa41EZAqi74PRA7wJFbwr0q5TC6/pvS4EV2RuZbfYFddizIhHdAu4Oiflpnml7Cmw4Txw/k=</D></RSAKeyValue>";
            publicKeyXmlString = "<RSAKeyValue><Modulus>hhjhOYvcx6I2qwtLbE2k1wmYO3c46S7Ay7U4/3yaNgaNXXXSuzCux0y6vLq1ucu7sJISPklayGHqYPzOO9oDpe+MB44g1btuWyEzj162+JPI8caU3Wqu5IP9WVjayG9/nvEmCvB4TuoopoxLdX9GZvLvI2SdBfa3r0T9tuX4J2E=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
            TestGamePass(privateKeyXmlString, publicKeyXmlString);
        }

        private void TestGamePass(string privateKeyXmlString, string publicKeyXmlString)
        {
            var url = "http://amlitek.com/";
            // Tests valid data
            var pass = new EntryPass();
            pass.data.userId = "Foo";
            pass.data.authority = url;
            pass.data.expires = DateTime.UtcNow.AddHours(1);
            pass.SignThis(privateKeyXmlString);
            Assert.IsTrue(pass.IsValid(publicKeyXmlString, url));

            // Serializes and Deserializes
            pass = EntryPass.FromBase64EncodedJson(pass.ToBase64EncodedJson());
            Assert.IsTrue(pass.IsValid(publicKeyXmlString, url));

            // Tests invalid data (userId modified)
            pass.data.userId = "Bar";
            Assert.IsFalse(pass.IsValid(publicKeyXmlString, url));

            // Tests valid data
            pass.SignThis(privateKeyXmlString);
            Assert.IsTrue(pass.IsValid(publicKeyXmlString, url));

            // Tests for another url (invalid)
            Assert.IsFalse(pass.IsValid(publicKeyXmlString, "http://example.com/"));

            // Tests invalid data (sign modified)
            pass.sign += ".";
            Assert.IsFalse(pass.IsValid(publicKeyXmlString, url));
            pass.sign = null;
            Assert.IsFalse(pass.IsValid(publicKeyXmlString, url));
            pass.sign = "";
            Assert.IsFalse(pass.IsValid(publicKeyXmlString, url));

            // Tests signing using "public" key
            pass.SignThis(publicKeyXmlString);
            Assert.IsNull(pass.sign);
            Assert.IsFalse(pass.IsValid(publicKeyXmlString, url));

            // Signs using a newly generated key and verifies using an old key.
            string newKey;
            using (var rsa = new RSACryptoServiceProvider())
            {
                newKey = rsa.ToXmlString(true);
            }
            pass.SignThis(newKey);
            Assert.IsFalse(pass.IsValid(publicKeyXmlString, url));
        }
    }
}
