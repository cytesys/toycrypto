#include <gtest/gtest.h>

#include <toycrypto/hash/sha1.h>

class Sha1Tests : public ::testing::Test {
protected:
    void SetUp() override {
        m_hfun.reset();
    }

    SHA1 m_hfun{};

    const std::string m_empty_digest =
        "da39a3ee5e6b4b0d3255bfef95601890afd80709";

    const std::string m_fox_digest =
        "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12";

    const std::array<std::string, 134> m_cmp = {
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "6dcd4ce23d88e2ee9568ba546c007c63d9131c1b",
        "801c34269f74ed383fc97de33604b8a905adb635",
        "606ec6e9bd8a8ff2ad14e5fade3f264471e82251",
        "e2512172abf8cc9f67fdd49eb6cacf2df71bbad3",
        "c1fe3a7b487f66a6ac8c7e4794bc55c31b0ef403",
        "2d2929e0f1bca99d9652924ce73b7969d33ff429",
        "f9b2869de6cc9226b990d83f805ec83915cc9c85",
        "c08598945e566e4e53cf3654c922fa98003bf2f9",
        "1cbbd7d768f77d4d3f24de43238979aa9fa1cd2f",
        "c71613a7386fd67995708464bf0223c0d78225c4",
        "004537f3b1fd67347489185a1c4b55da58f6edca",
        "2b52d47ab698ccce79ab6d0552e98f87f8a3aebc",
        "91dd8a106d38bd458250b80314a3b4837acfa85b",
        "9108c1fc03ff53527f9d9de94d9c151e697e154d",
        "343ad63c4d45b81d945360c080b065c98c7a8351",
        "19b1928d58a2030d08023f3d7054516dbc186f20",
        "9ee276acbf8a1257a58a5bad22bef8907e49cbf2",
        "3a8262b7c3b43877389d300986b0c0b1eedfdfbf",
        "1a6372d15d776f9879d300e51ec145363cd63667",
        "ebd3d4adf97066c84b8ed17d6bd1e270818763e0",
        "29ad0c6384182c5c2d4c953e200eed245467e503",
        "d088f3b187a0957d72b5d5645939bfc4302dffb8",
        "293efde746444af8e7aff0ad1a57c874cdc50966",
        "4f130f23896bd6d0e95f2a42b2cb83d17ac8f1a2",
        "a92b995e293d295c4bbab7043cccb030bef47488",
        "ed641f05795d5ee712d1e6ddc2d5146079db9dee",
        "82e757683db0b0417976c1661f7b020ae5225b80",
        "7b92fac2f01809101168d085e9f1ef059b131be4",
        "41be845b8e19da10e18a6bd3105793484d22bd53",
        "2a22d32e957a9de69c50e8f52872e2dbf1d0745c",
        "ca75e66a01a2b5b24f825f569d5ddeead3e50e4d",
        "43d83b2e816a89cac876f16530b0b625585c8160",
        "e04976c6e1ce44aa1840b07b57021c158a11eafc",
        "609b3f4ee88fd429c53d51dca7ace87711e7d48f",
        "4c911f83e9b42c92b8ea62135fa1bc0e727ce367",
        "3c8a34351337e8f5376092d3f329767c8035344d",
        "0b314daa55be9ff60f4337a25fef266036aed20c",
        "35309ec13ef8d90aaae172e4cf437eb16ddbf6d5",
        "6784f01a2b317aeef2ac03660dafa3270f4d420e",
        "5cdbb64242d8551a7cf583903fd7d5b72b277537",
        "0e477417eecfe482fd137e4a038fb5cf6dc7be76",
        "880b405e8e5059e3aa1797f662ff4a0cfcbce20b",
        "885dd07854409bf8cf5443652fd6835c23423338",
        "a7da128970268478e46f9585d0fb6297349b9675",
        "06bf9b84f2cffdb4b343ef9b3ddd1847f9b6ce3c",
        "4683b63a087f88e7ada2f6e3eceb4a0e9f7195a1",
        "b459efc276e7c1e39f997ed6c9b4f692dafd30b5",
        "8b2177f39b224cab2fb4df5ee4827fbe7115ce44",
        "d52bcfb557dd3ed70968f8835ccff3c924885631",
        "080316afb4e11d98120b29d1070ce749f1f0a32c",
        "4456f6c537924b7d47e430050d92bf6949a1fba8",
        "defc08198e86f88a007ca10f10d8af0d402ffdc3",
        "55066b480654e5846549494b863e3cd34bae76eb",
        "18b837ae2f9a204a7fea6d6a2ae5174365137861",
        "5021b3d42aa093bffc34eedd7a1455f3624bc552",
        "6b45e3cf1eb3324b9fd4df3b83d89c4c2c4ca896",
        "e8d6ea5c627fc8676fa662677b028640844dc35c",
        "e0ed6b6f61dae4219379cf9fe19565150c8e6046",
        "ba83959b9f4a8b3ca082d501e7b75ce73992e35f",
        "c9c4571630054c5466d19b5ea28069dc71c72b68",
        "fc202c022fdc439b99892020e04fc93b4ee8448a",
        "0dc94299f2d293a48173f9c78a882f8a9bffe3b0",
        "0ec86b3f3ac34ad860fa8da56bcca03a54018049",
        "30b86e44e6001403827a62c58b08893e77cf121f",
        "826b7e7a7af8a529ae1c7443c23bf185c0ad440c",
        "eddee92010936db2c45d2c9f5fdd2726fcd28789",
        "d0c9def032806d32bc485ea5493e34217d5091c9",
        "01ae707f5f6574b061a4643f59c98277da6544a3",
        "4b4e4f859b006e5b0afe2dc2806bae2ab3cb55b0",
        "049dbd0c7c40ce1a9a322531c994778cae8f3f0f",
        "d0929751861c93c786335ead7d5b5c066b3a8cb7",
        "41f9070504f9c81abfbb614daaec3b26a2f9237e",
        "4fced99ee1b5cb0dd68a5c5a194b79dc70841d43",
        "1268a031cf339eb68968e87334574862a95c4d48",
        "b17654dfc615ef4a8dd86d53f5dee434bec61143",
        "e106fa6de4ce5177f0d2fd4b7bae8478456dc25c",
        "ccf93ced5c9a95c23ae36936b7ebff088c991919",
        "e5e8a4e450be9938b318a96a5f95b12733cb39be",
        "c958795890d309b7add6d6432b510c297375e5d7",
        "2d5d85dfd3361150e8bebe7cb730c08258206ba6",
        "259c4c06d026726ced06b9d81cd3abcd5e936393",
        "736545c3e47672f832d54171c88b213789160c8d",
        "3da1e7b5188c2fdc84aa4e3b0b2c05c93f246e2f",
        "dbf2a20a9e1ebe314e8da8a678fdc6949750b9c4",
        "bcc9fe3fff88ff66df70c1e53401a28c5873bd63",
        "54c4ba90ae95dd2dda25ce8eaec645ac56052845",
        "1e34b919b2b449c51c72c4922e7d4841405857f1",
        "0ac5a64edb54535a9d71ccc853a1073a5f2001e6",
        "792534345f64f4d8cd1457ce8edf3e067cb5666f",
        "9a2f2b83877c65c955ab6a6c239357fac93609a5",
        "5cd33462b7a8ffbf17dda2b61911377658a96f26",
        "768bbe547a68238aecbbdddf78f517227e6ea98b",
        "b70f0297e92d4b1f5ae01618d7ed6aafc2dd8404",
        "6675ab9c5ca21f903e070ea1a217ac655584cf55",
        "84e94d95ec69d965d0b36ca3a9ce5dcd4ec84bab",
        "4e3872621039b359e7371bb9810430a5a2c78195",
        "81ad592e1a48b35db67cf02705566315f2c149d1",
        "39ba29cf0bc73595d1476abaa413ac968cdf8fa2",
        "436bab78a2b10f04528d408c922fcdfba069419c",
        "7a4a9ae537ebbbb826b1060e704490ad0f365ead",
        "faff6d54393e420b1de1ca3ef1bd3be191109949",
        "729d3390d130986cf50f54d70320a078c483e2fd",
        "da77d1e4a87262b6f8ca0ca66f8eac7e36e29e12",
        "c6be529a3b747d5e9efe6881f7ba93a62326406d",
        "c51d4fa580fbace5a9703ff2150bf1e5e33ef1c8",
        "ed819b4336d64c93a27849324a3f984c6161513f",
        "53a5d27a01bf990e098fa3e9421995516bff6f4d",
        "53425c86a3e0700c77fd349d45b095a220184a91",
        "b2984971cfa2da84069f3531076d222724cd6556",
        "439bd45a91ad4bd895f5184d01942aa597dc71a6",
        "877ae93c5926cb90effe5f05f59c4bac9bc71a6f",
        "2760153e60cb7bc96eb59a04ed2db5de4a94edb2",
        "f50d9accf3d7837bcd0983e1ca6347f9aa53996f",
        "bb06f65c0c65e8a293cce59af7a4887e963478d3",
        "c8a085ffce054c3c3a9b1827ddd974bbf4de4181",
        "a6f9f65377c2715aa029b19128a3abc1aa64fda5",
        "2f98412fb385adf4365467f2d992f768814e5799",
        "aa83bf9ec3fe30734d1415badf17b8da358f4b54",
        "293e3964d2b4d4ba9d21991b8388283b4f09b935",
        "a1298700a534e357b7130c74e277fe5428d43baf",
        "b9bd07da310bbf697d195fd2c2440d567f33ea95",
        "d712ce221db9a78a2ed64fdc5f3d6758c1cb3c46",
        "932567a1cfc045b729abdb52ed6c5c6acf59f369",
        "f84d4ec48808a1b0afe0b1e2c62a5dccf52f9ccf",
        "9d3953e922387b19a2f0e7f27ca2b790dbe57dfb",
        "2ae9e1bd10bc490766de002cd5b73917680cc26e",
        "8c8393ac8939430753d7cb568e2f2237bc62d683",
        "2927490ade868795ecdd8febe05214cbd243ef35",
        "a61aecbe0691f04f4c4dae8770187c24f1ef0fe9",
        "316a25c625a5e881321aa8eb483367df94aa6190",
        "6fb8ef977523f0b57c22ef21a40f11358af33681",
        "0c2e411601841cdb09033eb4a4afd3bc82811495",
        "58b65321356d78b7fe4c517ca264088b430bdcf1"
    };

    const std::string m_7000 =
        "81b8d15acb6da00ba00cc493805e023f3ff6b981";
};

TEST_F(Sha1Tests, Simple) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Sha1Tests, ResetWorks) {
    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_NO_THROW(m_hfun.reset());
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Sha1Tests, BasicInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox jumps over the lazy dog", 43));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Sha1Tests, ChoppedInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox ", 20));
    EXPECT_NO_THROW(m_hfun.update("jumps o", 7));
    EXPECT_NO_THROW(m_hfun.update("ver the la", 10));
    EXPECT_NO_THROW(m_hfun.update("zy dog", 6));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Sha1Tests, Extensive) {
    int i, j;
    for (i = 0; i < m_cmp.size(); i++) {
        EXPECT_NO_THROW(m_hfun.reset());
        for (j = 0; j < i; j++)
            EXPECT_NO_THROW(m_hfun.update("A", 1));
        EXPECT_NO_THROW(m_hfun.finalize());
        EXPECT_EQ(m_hfun.hexdigest(), m_cmp.at(i));
    }
}

TEST_F(Sha1Tests, SevenThousandAs) {
    int i;
    for (i = 0; i < 1000; i++)
        EXPECT_NO_THROW(m_hfun.update("AAAAAAA", 7));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_7000);
}

TEST_F(Sha1Tests, UpdateAfterFinal) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_THROW(m_hfun.update("Hello", 5), std::invalid_argument);
}

TEST_F(Sha1Tests, DigestBeforeFinal) {
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
    EXPECT_NO_THROW(m_hfun.reset());

    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
}
