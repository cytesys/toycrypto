#include <gtest/gtest.h>

#include <toycrypto/hash/blake.h>

class Blake224Tests : public ::testing::Test {
protected:
    void SetUp() override {
        m_hfun.reset();
    }

    BLAKE224 m_hfun{};

    const std::string m_empty_digest =
        "7dc5313b1c04512a174bd6503b89607aecbee0903d40a8a569c94eed";

    const std::string m_fox_digest =
        "c8e92d7088ef87c1530aee2ad44dc720cc10589cc2ec58f95a15e51b";

    const std::array<std::string, 134> m_cmp = {
        "7dc5313b1c04512a174bd6503b89607aecbee0903d40a8a569c94eed",
        "6edae8cc24a57fbad640075d5f840ed0d216d5b1ac6870ca31973fb6",
        "c1a3b480e11801e36d92a337b8b0049c965da8662fcbdff3b86e83f0",
        "5bd1019e9ae327cc599e33020ac8d11971b81c94ba9b6943c8ab9d42",
        "29a7331e595c8d88a40dae3ccebb1830a7462f7c8ca472dd0e0a39ec",
        "8886aba3a0a12a873ec0ffcc9aed3074e570e8fa977fa2707768f76b",
        "887cc1e6495ba8269499422292701e6ccce5862e73f91bbca037c588",
        "994ea676ae73fa3a2fcb3ae9634bbe6c1817c03c00f700e70a3e4d5e",
        "2c9d85b5965edce60aefbfddc60d37d9c478d5b62e74336fb98999e7",
        "3b92a532498a38efa7d1d4f0e6571a99ce765f4ae98b83e3806bef06",
        "ad4bf3a0d3ada6c274c081a970d03b5bcba90799ac607e4a27c9f315",
        "907405da28a5bc6b3d346767b6b09fcadd6d1701b4bae573f317990a",
        "8e427cdb305ac286187a922202080201f614d0a2fbe5fda5a04f1f95",
        "0e3ac5b7f7a78ed96e4f3a54d0ba4cf4553ad39b06db41edceaa4a1d",
        "528a9b4eb575991a8881efb163d5a2a1f50f0b10b56933754ead7c1c",
        "b753695f4e090abdbb45cd08970d007a698f2d014624256aff621294",
        "46a56889f4cbb14eeed187cdd62ca99cd68b9a0baf33f3d7a5963ce8",
        "38d8096973c58fdb7ecc2a68559ec4311be17cffbb5862a6dbc3362b",
        "cbd8db15d53ece16c2f85cb7bb24aee7b5178f58677390af06100456",
        "9119c189e7222afe15c4bb7ab9fb9a579c3cd7450d9cc0397577e236",
        "e7f7b8f0b187ea6d295d8fd4b7a1ad15b0a7ce2e5ea2376c218ac162",
        "d35ce57c2e8bdf452c5a051ce207f0306f74ab4c70a0b7fb038ffb68",
        "c4d690996b9cc854894585aec589f9ec997642aa1251daad7dca9b01",
        "e961ee8d6cba6ef9d4160e5def3012348aef2e9a17a9538d6642fdfc",
        "53f0abe5c6f3e792ee60443b1412da21791816f3c17b3930e2b77b96",
        "d1cd9bdff3c0859dad02499795651386e7d670abb1810757895d54fa",
        "9f876037f0574f1801db4d2dbaaba51fda85ea13657835b1b052d9d3",
        "512b1908641abad32829b0f65bf2fd635e0c6893b74d6edb09f4a4a9",
        "a14ffbceb5acf0a2eeecf2188a2b8d0a9ac31a57b868f5adca60d281",
        "3a0e5a75771997324e0ae6c60a5e8370717e002b2b2dbcf7e72ff79a",
        "22587c5363b559aca1a8222056c4af640ab8e2e3549be93a01996623",
        "d7b746f1042ebacf5a9b9b4fa2d821aa3bcda77c3c1e16a8f97e2e67",
        "a734ccb26b7c0f47bccfead990f2fe3790f5227bc9718d10a18c7aa3",
        "fb8d6da163397a38fe3db489d729f8e7fe675e7c079bfb21c618e92c",
        "1e551b90fbdc656bdfabba6f073b8eb35dd0758475a35ea350b59f1e",
        "d368953c32a2e4489a51d0de8c24c49e2febedd98f1aa3e53c1d59ee",
        "4575a61fcb62784fe9a0631ee72594b509c950e9d9c4ebfb18b1cce9",
        "a0cec4e125054411a186f2ff3596bf57f944d052df8924808814739a",
        "debe6f8435c9aea57fb8f2e47d5cd1c9d595c93f4da9c8f7b0a7467f",
        "a87e8c643c82a4b9fbd103bf994b98c7e596669e3498819838d10cb9",
        "3c2310856c271ac6d9da08f9639cc6833ec5b2dd930e5da902f27257",
        "239a5caadd5fb2721b74a4f87741430dad315b636eb4d3e01cd51b8b",
        "a5d8761c51510a632ff82431090fbe26067329b933515ae20c9c7a98",
        "4b75f527d007fe744b05b3db5333e480bc429afdf785a25fe8f21b90",
        "51f827b2bf25cf58241e37dd8319d6d5d29041d80af44a6427909b5d",
        "c0e2eba1dec9aaa312732e15b0fdbfc0e7e61a1ec0fd5f3d67e53ee0",
        "fa0ed3207796e8fa79a3a844e993b2d686eaef3dc05e39c44311ea00",
        "b9b69c95bd2e3c2c616bdb8b0e0e78c0470d7ae7f4ad09672b50e227",
        "01624df2bffe29931245e1abc0e12095b6e06568f4995e36acc4db82",
        "2c3ce96f8d07b24eee4fd991b9df2c303607de50e70e4454ff55cdc9",
        "0c644a5735569982b1be43ea20eb4475ad784156556342ae6ca4960c",
        "a903fcb842cbd66413936dfb0388ef6e9b3fb65ea1e18bc5b53c7625",
        "00e48440035a279e3fd818d6964046e95e7cf771fd97bb8557f7e58b",
        "1f8d7e697f5a2e12d459acfc5f7b9644ce31d6165801d815de732f01",
        "dc95618d1012d553899916cbb78259f9d8d66408ac7a4383696b43b7",
        "6078264b173b1767875349c2b6d2e199b3cc4f6360f9dbcf41d49b31",
        "f4d07f2ecaeb82f37b7ef2004f72fa9cadb092db8d4db20c66948c50",
        "9b96099bc34fa422350665f86220f79b73e651d8a3e919ff9a85353a",
        "3b14fbdef5c6d1c5ca3354a897c32be9e2ee2896173b91e41915cc21",
        "f7c7812e2e790d428b099038e1060c30e27dc8afe050540302695ef7",
        "ee5e44e2db8a5529b1a1f0a933d3dc9435373f2b18f20ded8b1efef4",
        "6a07d8fa1608ac4038a11a39a276721f66343a8e9c7f851de9adea75",
        "fc51fc4e0baf65f2521c79d99710d9e828b532a5de00e36b2e4c28f9",
        "8195db69e5d071b09275fbaa22720db80624051949e52a2e4a91248b",
        "b91f43b91b5afffe5e8a6d16b522ffc0c4fb8b883c1a865f3928daeb",
        "fdb2827d5949dc3077d98414dcbd10a6fc7e1b183e1850b23a1085f3",
        "4c1e6c3fa2c858e27945d9559eb45da70acf5fe80f0cc9a51e9a33d6",
        "c4dd34e496b074fc3f58630e39737e885aad7487930a32473164e3b9",
        "c16917be7847f13f8b61ddded5979fa608f2193304be345e23cc2921",
        "2d39bcd4698d4b75cc5f0e15fe648c82286b7f552818597dc84a8786",
        "3610a00f257eeb4ab19196347432fbabbae75e8a0eeb6ce36370f1e1",
        "d37f44953f57f00182beb0b2893469b745624d10a28d2be2928cfab1",
        "7c10da2ee8b8c0cf3bf541f4242ad322877534ef8db42d677260dfdd",
        "b3774b42a5033841d23d5f00343d1d7b0fb8170ba852a578e159ecc8",
        "6a838d31054914437046a7cd23cca54fd85f0af3614473d464bedcca",
        "a48f55b30205ce8aea821c52eadf93d0044e23f0c0d52e862365ed64",
        "8fd856cff2d93925f06adf03f00a45902f91f030f85194db4c526795",
        "70b7cb3817098b44b642bdfa13b676517817b766a932c63516cfad21",
        "42c1231f1b3a9a01f7143c814021c62201c41cc79a960e1e293a5144",
        "b5b964af8feab43236b727e2e20edbe088be45b944d7d826f37f5a2d",
        "3d31b836b2fb2bc562b8f8b78bd40f6e492df80fde232773239b9f9d",
        "9d4d65c3737ad64303e65ed6e8bf681dd3f4fa7c9ce454f6df3fe906",
        "f9eca3896178d4c6d0355dbbc163e281dc16bfb8a3817d1eb77efd8d",
        "98ed550947a7f0e481be6acec75b87a9a71c7f8d5e8416c272c1cafb",
        "720f4e304bb9aed21545ff884e727f293558d8896983258dc8f9936e",
        "7527b4187b5fbee27b800b71e9c3d1542b00a6ce26c732bd15108e73",
        "57ce6f3836937a5a6837dbd4939713c8c11916c8454fca9a189af5bf",
        "ddfccd1f956ed2c91644b89ded0d559e21da494e235400193674cc22",
        "c0bcbc01b57148a02831cc6bd8f2474ddbe93c174fedc4deeb82c542",
        "56eade770a465c01ee0bc585641599f6270e696ec427e21d4313aa3a",
        "c6ff0f0ff894a342b5fb7ef9f71a25a67ccba0edbe0e3fdc772df0ff",
        "42fbffc9686647b00dec7d2a4a2c042fec29a830350827ad43cc0fb1",
        "3e328af4e2d761fdc470b8c879a61193cb069f3da0ec315c0af68a3f",
        "797ad5362b98d66c09d2b7c55d9b7d35c7dbd205d03edddc62335504",
        "1af7d73881423284352e5decf9f835f1c914208d7d380f794178caac",
        "dc5f6caa9da5f7504c53124f29d6ef5277cb6da39fdf3c87be60ed0e",
        "efcaf1fe122563997b8de5be5cffe1d772ee8d224d273fce5ff1b0ee",
        "1c04a4313d12005548fe7b21573b3ff7e8840aa044ab2253db4c7b97",
        "60dd1b7a25744bde18fbf06feb262e2b69216aa05a7c579da6bd0f59",
        "646ee745f86c20acc2f13830b07b02dc7a046d38b49236480c1d31d1",
        "1504823a52a78f4644d5a5b2e3301c7424e0341fbca3c40787277195",
        "eed830364c97b2ffc06ca1cbf17e6724c1d1d76f089da2662bfded17",
        "964ef58c153ce4eb1f42bc84fda8c21db05ab8bcea5754a28f3db804",
        "143b8db4cef02d3f4bbd560b53fe68509c79158164544ad3fc3463c5",
        "2775d976ea4a9e7f07bbfefa6014a74855f250d1c04c834e5ef715bd",
        "85c7cf1da2b983298d6a5d7dda65c18bf6e3977db84e2a4dfc2d918f",
        "1e4be633da6b868ec28732bcdaec1115bf9d1197c0e1512257ab0fd2",
        "0f98b590ff1c4982e91e480495314b5162607f3f3db262a7a447a63c",
        "607129d1e749b06c53d9308c8593083bc7938f255e5e8849f1a3c85f",
        "e41b51a47b98f7185cc7f14072ea1d106425a02453ccf3e46adc2218",
        "fd37af744ecabd1e16496412aba1fa6c488fc11e7a016213a328528d",
        "2bbae405b7e281342ee83e0652af167ff3419f1a37f18a01b16a0a50",
        "fa15ae378dc037a6b7adae1b1672d8182dea21c6b8653b25ef9ba33a",
        "6451e51a4b628f22052c6c2adc666226e6a210bd6cace8efae398c03",
        "a8ad568979ad4170198d726e28dd8e54484430058f729f35ca956538",
        "60db344a018b3c3bc401e0a261b46fd761a483b997d9b0b889c22e62",
        "db9ba6e3bc5f89b95b80e583ebb24c85252839c4d2c59c5b52e44ab5",
        "c647661c35c585be2ef2bc81139ad056a8ea449dc371e83e2922ff76",
        "ee9e05b85ddd678fbc4da4b1152454ca633f5207fcf7b8eed3147f68",
        "44e03b61a57e52581d854796e24e3ea30e3d4fbf23dc9c481488ff79",
        "e593a30bce1cd6fdead140bbd2eece131347cecef21edcb792d5b488",
        "bd08790b9a4e702218e6eb578178e576a74be14780db3b583ea70a3f",
        "5df717f2c4bd885f96b84b380c4bf559ba3f94f520a161e93b6520ea",
        "b6609d7e26e7d1f82ae7342516bf5a959b7572f258ce27cf55349c54",
        "8468ff3f98f8ae337d4eedcb33797670d00132c0e97ab9160154afe6",
        "ad6c6ac988389a4094ae0d493bd82eb112e0c83b777db391d6b7ec71",
        "862e95cc653597cb49e4273e8b325daaa4655832964e47826ac2f455",
        "878c7df4d5f5cd48d407ab77e1f46d51200174f665a10012ba921dca",
        "1c5c897a85d5019da524bcade111e6738a3135f7a0d7c65f9c15b5a7",
        "0ae6c0ed9ec1e45ee9b880116f28115356a463e6909e1ce60fef3830",
        "68e2d1b409f71f76d0ce79e79d7ab5627e15ce33fb124721ffc8c024",
        "45d015603053d0f87be051dcd3ebab771d350ef3d7bc4c6f583fa254",
        "6644bd197e495455f0bc4f4e74890e9696ccc9f46b3b69b5834824bc",
        "c6257289ec9853e746d7fd2c3179194056cbb23ab43963039b8a2bf1"
    };

    const std::string m_7000 =
        "54840f6363f060588b195dd4c92a6bbc32a1bf713479da48b38c5448";
};

TEST_F(Blake224Tests, Simple) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Blake224Tests, ResetWorks) {
    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_NO_THROW(m_hfun.reset());
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Blake224Tests, BasicInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox jumps over the lazy dog", 43));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Blake224Tests, ChoppedInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox ", 20));
    EXPECT_NO_THROW(m_hfun.update("jumps o", 7));
    EXPECT_NO_THROW(m_hfun.update("ver the la", 10));
    EXPECT_NO_THROW(m_hfun.update("zy dog", 6));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Blake224Tests, Extensive) {
    int i, j;
    for (i = 0; i < m_cmp.size(); i++) {
        EXPECT_NO_THROW(m_hfun.reset());
        for (j = 0; j < i; j++)
            EXPECT_NO_THROW(m_hfun.update("A", 1));
        EXPECT_NO_THROW(m_hfun.finalize());
        EXPECT_EQ(m_hfun.hexdigest(), m_cmp.at(i));
    }
}

TEST_F(Blake224Tests, SevenThousandAs) {
    int i;
    for (i = 0; i < 1000; i++)
        EXPECT_NO_THROW(m_hfun.update("AAAAAAA", 7));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_7000);
}

TEST_F(Blake224Tests, UpdateAfterFinal) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_THROW(m_hfun.update("Hello", 5), std::invalid_argument);
}

TEST_F(Blake224Tests, DigestBeforeFinal) {
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
    EXPECT_NO_THROW(m_hfun.reset());

    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
}
