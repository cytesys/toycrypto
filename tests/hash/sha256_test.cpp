#include <gtest/gtest.h>

#include <toycrypto/hash/sha2.h>

class Sha256Tests : public ::testing::Test {
protected:
    void SetUp() override {
        m_hfun.reset();
    }

    SHA256 m_hfun{};

    const std::string m_empty_digest =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    const std::string m_fox_digest =
        "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";

    const std::array<std::string, 134> m_cmp = {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd",
        "58bb119c35513a451d24dc20ef0e9031ec85b35bfc919d263e7e5d9868909cb5",
        "cb1ad2119d8fafb69566510ee712661f9f14b83385006ef92aec47f523a38358",
        "63c1dd951ffedf6f7fd968ad4efa39b8ed584f162f46e715114ee184f8de9201",
        "11770b3ea657fe68cba19675143e4715c8de9d763d3c21a85af6b7513d43997d",
        "69dc6c3210e25e62c5938ff4e841e81ce3c7d2cde583553478a77d7fcb389f30",
        "0f0cf9286f065a2f38e3c4e4886578e35af4050c108e507998a05888c98667ea",
        "c34ab6abb7b2bb595bc25c3b388c872fd1d575819a8f55cc689510285e212385",
        "e5f9176ecd90317cf2d4673926c9db65475b0b58e7f468586ddaef280a98cdbd",
        "1d65bf29403e4fb1767522a107c827b8884d16640cf0e3b18c4c1dd107e0d49d",
        "dd20088919031875b7bcca29995545dd40ca994be0558183f9b942b51b3b2249",
        "0592cedeabbf836d8d1c7456417c7653ac208f71e904d3d0ab37faf711021aff",
        "3461164897596e65b79bc0b7bee8cc7685487e37f52ecf0b34c000329675b859",
        "14f99c4b0a6493e3a3f52022cd75276b4cff9a7c8eef74793267f687b600af96",
        "6f9f84c09a5950e1ea7888f17922a69e5292dcbcb1e682ddfc977a9b4ea1a8c0",
        "991204fba2b6216d476282d375ab88d20e6108d109aecded97ef424ddd114706",
        "444074d5328d52b4e0036d37b1b6ea0a9fe3b0c96872d1157fbf01b6fdb2ce8d",
        "d273c6b6de3f5260e123348e0feb270126fa06e164bb82818df7c71b30ab0ef5",
        "234b7f9389f9b521f407805760775940d79a48188338d02a1fe654e826a83f69",
        "edfcaac579024f574adbcaa3c13e4fd2b7f1797826afe679f2144af2cb5c062d",
        "f48de1653fdfa9b637b7fb4da9c169a1f2be6a1ec001e3d2cca44c669a693ecf",
        "8a5bdb4cc15164126c6ef2668de9dd240d299ce6397a42c95a9411b93d080ed8",
        "1786ac1492c6c922c2734e4d3d8e9b030cfba291a72bc135989c49fc31171ac2",
        "1bda9f0aed80857d43c9329457f28b1ca29f736a0c539901e1ba16a909eb07b4",
        "6724431fc312ba42c98b38b8595a49749419526aa89722c77a85c6c813dfdb5a",
        "06f469c97c14e84c74853bb96aa79305eb4f6635291bf1202c4fdadb82706204",
        "568f214d529544bf4430513c2993495a5b434611533c63d1cf095b51c5e1f8af",
        "c84f7630cbe823fc4d80f605b98294592f15b14db1f78d6f18e686c1f8cb5ded",
        "a7951e0ca2e9612a985a36747309822a67a9b8c1a5abd848c03e82216c85f1b3",
        "37b9403cf88cc2639d0a118d757a43a0ff6d4871823707ab6a8bb56bc68e8e79",
        "55ee740f58335c97d42c32125218eb7c325fbe34206912f1aa7af7fd6580c9a1",
        "22a48051594c1949deed7040850c1f0f8764537f5191be56732d16a54c1d8153",
        "5d873590851b7b00b60490c8e6966b3409c385adcc9590d801f0e03e268b5ba5",
        "1e98a405718c430a4067d75125015a947a971449bc433b078418438c48bc6046",
        "015c50632207f69408c05d20e36facfad9bde74c727f933023f54cd6e8b87372",
        "a3b99d59dbb025726312e812c2821cfbe55189f515414bdabd5e3d284c8ad6f9",
        "7d24c321bfb2a5b6d2c7a3c2948855cef421d08352dc296ed95c6f645fcce441",
        "876fc5bf6bde065afea543aceb645ce17ffe3c9d8df9c6073ab31f3a562f4257",
        "b9b515854e040b8de31d85d597aba28db4467fd0a7d6eb77a31005f4a67a8fb3",
        "f0a2fb80ac0699075fb6c7b0ee2bcc204a1d909ee3149571216ec9cc1d4b9f8e",
        "b78244167af116f2b3597b4a81421bd2b28f3d8bf616025a5ae424f689fd7632",
        "d85ce644bf4e82cee032eaa5c3d9030a090276d9bae3703112bdfc6f8fdde307",
        "0f007385b6f9d4b7eeb2748605afe1a984a0a3bfa3f014d09e2a784ce9e5cd1a",
        "b06b3f20c246db70a136e3ae4787d0df96db4f693d215c21883d3c19700fb276",
        "ac752ced452069c55c7567a0717b87615824c568dc98c8626ac85fc34b234c3b",
        "91a07088de2d0fe9f31567b05d290e65feb06758d000ec463f7f5a6e82ce00a5",
        "abf6c5d1b6512e188f1da6a72e974f7b98b5bac62453f1748c8f9ab180803fdb",
        "4739dcdbab0c377161c539af55d47c5c90c87807d0728aabe91697b66e29096c",
        "ff85f0693c8e6bbeeaa1f90c32e1159b9b545d830ffe58cd80cb94d9d8140d21",
        "509ddb85fdf92f197d32570c005cdcb6dffa398f088bd1a013459f6fb1f730ef",
        "1d31616e307323bd80775ae7483fce654a3b65bced7134c22e179a2e25155009",
        "3e1ae21112ec8fad05e3676e1940da52d56771162142aac4d73743e7df70b686",
        "5f2671f97427c8873e5af72686d244e4c8126a4f618983bae880a48a834a0607",
        "2d0009d7df28cdc6b5a4c36063d97415a8fe99515317458fcb0b0e2a821dbcb9",
        "8963cc0afd622cc7574ac2011f93a3059b3d65548a77542a1559e3d202e6ab00",
        "6ea719cefa4b31862035a7fa606b7cc3602f46231117d135cc7119b3c1412314",
        "a00df74fbdadd9eb0e7742a019e5b2d77374de5417eba5b7a0730a60cce5e7bf",
        "cee244d999f8cf49f2a4ee4d89695130c9c95c33538cedf0306881ebd42714d2",
        "5b29354ee33cba5b924ded5e3c873a76e1d12527d824ace01ff9683d24e06816",
        "c5fb235befd875b915fa6c4702a7abb93cacf3d7c414b71cbeff9e1b0a9fbd41",
        "0ae45129ef1edf64309559f6cb7bb0af16eff14ad82f24d55fa029c1b4144078",
        "5a2aafcacb9828e41fb7c8f8098952638645874b3a8ca45d2523fb2d5fc7166d",
        "1b58d00f5b1fbd2a1884d666a2be33c2fa7463dff32cd60ef200c0f750a6b70f",
        "d53eda7a637c99cc7fb566d96e9fa109bf15c478410a3f5eb4d4c4e26cd081f6",
        "836203944f4c0280461ad73d31457c22ba19d1d99e232dc231000085899e00a2",
        "fd8afe9151793a84a21af054ba985d1486a705561e2a50d4a50f814664f5e806",
        "f495547fca5a5a2c40dccebefe40160efb8bc2888e8afef712b096b5f2585b44",
        "ba31b89f9486439fdf551f597fede0c10260f9b404866dba4a6555375f486359",
        "46f23cc7ccba8af67978bea568e63cd045be72aba974132b1b14cc59277329f1",
        "01d3a187638cc1a7740a74fbeb57aa2648dbdec42d497321912bf393d283ccd1",
        "96b437b3df7c62fc877a121b087899f5e36a58f6d87ba52d997e92bb016aa575",
        "6a6d691ac9ba70955046757cd685b6257773ff3ad93f43d4d4812c5b106f4b5b",
        "beb869adc22a7e8fbd5af12cbf3ad36dd92dca6ebf52ef3441ed6cd0dff24dc6",
        "0f40cb2f3661d73dfaec511e8ebea082fb1f77db45bf8c9ba7c9708da6ba6301",
        "ddd5d1ecc7af6a5b0d18e0825004d3bc9d52e2cdf14bc00c7474f16941a64acc",
        "6a10b9a8a33d7814ce73679ace5c43657aa6d63169ce215fd85177c77a94147d",
        "9d887d47c78267827dac4afb2cbdcc593d1b89c1d0c1f22c3800cae7916962cd",
        "e45ca598e970afb0f1f57bd34e87065839d2fac524421048fbec489f68e1fd0d",
        "1581baebc5f9dcfd89c658b3c3303203fc0e2f93e3f9e0b593d8b2b8112c6eda",
        "d9b1f3e2c6d528668a73f22575c44ed9f98d9c684964761b621417efd80d7a60",
        "9feacd760dfda20e5e0accf9ddeb8b5c01276a56dc3518046a26f5276fe15041",
        "6aacf5279e24979684fab16fb5495c3ac1dfcf7138b0825376af83473d07cae9",
        "cd2f0deb953014ee400eddef094602d9676e0fd2269d22818f0d5bc198d44d8d",
        "ff9265df14681e44d170fd2b10c6cdf3991f731601d6b89cafe39691d3b42559",
        "6c99e32b005a3a4956b9406ab15411e666c7f67982db170ae1fb111ec634b9c4",
        "e1659ad54063a379f77fee108a376a6a7d5ae3d0c437bf847203963bd0078dfc",
        "572d07a66fccf05d5f73c913552e12d9ffb39a15d01a8fd48cd6aaaab86f4f14",
        "ca97d312ef8551820844548f300f9528f27d53f6ad3910ed2709f2b35c9591f3",
        "97654dc78f4f7d4cec4b4870e6ee0a87abacc89337ed0629e2e511e4466df56d",
        "fde923c1ed5e5cd32c629bdf341db32c0f72ba8f1e2afd9c194e87e0e3d9da5f",
        "d6624a66f3bcc4adef8a17abf9eeb1fbf23746165b2f90f9cb3a679a58e4958e",
        "8676909e9578a790f84be31fe94f4d22488f912b754ee816ba0a5c4a392305a5",
        "57f65fd8a95ff738b95dba0f1606025535e34591f1b58b00d33958093808360c",
        "f6afcaf794fe0e04d6ec18bbde55412a60c0c5ef55e75223b817e97f208bbccc",
        "6121f27b52c1f17ddce365143ba58a720fa303707faa32a4e5e89029f34ac618",
        "69d62c062d67d8d2ce9068c1898fb9746c911839aa88ad1628d090f4c8e47f05",
        "eb9f8b69313e19e14b1043b3cac05d18d40321536ad485be8145007aefa9295d",
        "b1cfb0f511886ca07ade919740ca95e1b3d998ba7cb66ba2badd53be28f5f509",
        "d0118863549f990558685da9090ca8eae8c809c5545c4aa85f8e5eec413b2555",
        "d82c6aa133a0fc25b087f46ad7ed2a3042772e612e015571e61753ff55ba6da8",
        "aac76dab773c00c8ad4bb128147945c70798eae5a2511fef01e853c6e3051ab9",
        "ccd77d7adb6178ee3e3560ba4583044a36b296257ae4c5cfead96d46af31fccd",
        "3c4f48a886b2de7e908d6a626074e7515265cc9d1188c161cf159fd376d3d5f8",
        "7f9578a31905e95a16cc9d3e7b57dc3158a23dccf359a1f2cf09e73eb13e5cde",
        "770492ebaee89a20d19f9972c3e3d0c7d51c9baaedf06fdfe9a7b69da3394779",
        "893785aaddea396621c31dc5d465e2775cbc6b7423dc3498e80aa5da7a6a819d",
        "1b2b69fbec485ef3f347ee6dc9c87d73505e45b5c9b02599b823ac94f5d642a1",
        "724b4b3d3e8ac7588561ca00eec11693f6b85c03bb6b1302d458a7a4ce4b39e4",
        "6a30ef4094128b6fa463b70cb21d141da92711d80ea94c9b73fb8a0471cc49a9",
        "50968cf735e3f6a47834ae3745816234f72fd156aef1bec4b6a7d3a3151773bc",
        "3ed01dd816dc93ea2d445681df11aa24e9fd1441de429eb0ee7816ccc09a2b7a",
        "64bdc48c731313c7b37c1f1d13d6265ac7a2604ff630b50f591a86e610cb3005",
        "96666c386cf99a74ec9eb55a5545aa90a3e53a8bbbe74cd3334b32d4968a3214",
        "33555a41335654a29d5b7799bf180915e09095d21991dacf071583957b9e3f35",
        "ffd391d554ce0672ae818a149dd55325f4cb933c97017b8148934474355d5a88",
        "cf2050114ccaefd8a0ea6cf31d85e0232eadc8fd61277ff16496d2234b55c7d7",
        "e42142b4243d5a2c59a2977d0385d49eab288085f8d38ead3ae5d87145c562ec",
        "3bb810492422cc5c7466d86dcd8095b0d87e97634656a3fa5fe2270a2244c16b",
        "17d2f0f7197a6612e311d141781f2b9539c4aef7affd729246c401890e000dde",
        "a4f4256159ea6fb23b27eb8c5eb9cfb9083475985f355a85c78de8f2fef2b3ac",
        "a36c4cf85204c67047c00d5dcc16677978839af0f0fde7ff973c98b66e244552",
        "4a596559f450ce5e3a777d952d8d2ed8611e9f3facc8400483371f6eadc4bdb2",
        "64855e54c94d14ab53afc6109d3c0033c665fab85b57c0e7d4e8da55b3b26952",
        "a2ee2228d4798988ce3ac273c0cd8b9bbc4e3e58413eb22dfbe6395758659a2b",
        "35c28ee2e25f5ad70384f1ca9723f520c955fb5fe9f2e56b9dc809479a9ca8cc",
        "da3f6a7f55f821760330dd14495e68e7d153b05e472d38459d4728d63ad9df26",
        "026134f6117e45a37c5c2dc2f330bdd274c6dc087526b91ecec4d6dac9bb7346",
        "b6ac3cc10386331c765f04f041c147d0f278f2aed8eaa021e2d0057fc6f6ff9e",
        "e7118c3a89bf814ded2ab232303565239253f59fdea93e27d0206e175492e3a7",
        "466a1916275bccba527763f930ca4a42a81f55e28559fb66108fc314cda386bd",
        "8e7209c814021f27d1c9bbe912c20fbf3722977d9ff34f1c3876e55a923fb955",
        "a6c9414139f47ccedf62c9e3d4a86d81e82a3e843a1e62ed07d9b090091d8a5b",
        "4f20a827b5a2a8ded6b0b42f4ce692cc2e6a907400110b1dbfc3062d07f06a91"
    };

    const std::string m_7000 =
        "30d27cdcb6c3872e9a5e7f564dbd24e722c5bdd01c3bd278a1f9b3528363ff47";
};

TEST_F(Sha256Tests, Simple) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Sha256Tests, ResetWorks) {
    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_NO_THROW(m_hfun.reset());
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Sha256Tests, BasicInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox jumps over the lazy dog", 43));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Sha256Tests, ChoppedInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox ", 20));
    EXPECT_NO_THROW(m_hfun.update("jumps o", 7));
    EXPECT_NO_THROW(m_hfun.update("ver the la", 10));
    EXPECT_NO_THROW(m_hfun.update("zy dog", 6));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Sha256Tests, Extensive) {
    int i, j;
    for (i = 0; i < m_cmp.size(); i++) {
        EXPECT_NO_THROW(m_hfun.reset());
        for (j = 0; j < i; j++)
            EXPECT_NO_THROW(m_hfun.update("A", 1));
        EXPECT_NO_THROW(m_hfun.finalize());
        EXPECT_EQ(m_hfun.hexdigest(), m_cmp.at(i));
    }
}

TEST_F(Sha256Tests, SevenThousandAs) {
    int i;
    for (i = 0; i < 1000; i++)
        EXPECT_NO_THROW(m_hfun.update("AAAAAAA", 7));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_7000);
}

TEST_F(Sha256Tests, UpdateAfterFinal) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_THROW(m_hfun.update("Hello", 5), std::invalid_argument);
}

TEST_F(Sha256Tests, DigestBeforeFinal) {
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
    EXPECT_NO_THROW(m_hfun.reset());

    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
}
