#include <gtest/gtest.h>

#include <toycrypto/hash/md4.h>

class Md4Tests : public ::testing::Test {
protected:
    void SetUp() override {
        m_hfun.reset();
    }

    MD4 m_hfun{};

    const std::string m_empty_digest =
        "31d6cfe0d16ae931b73c59d7e0c089c0";

    const std::string m_fox_digest =
        "1bee69a46ba811185c194762abaeae90";

    const std::array<std::string, 134> m_cmp = {
        "31d6cfe0d16ae931b73c59d7e0c089c0",
        "d5ef20eeb3f75679f86cf57f93ed0ffe",
        "14b4403751ad952dc0e8a0c627c2eddb",
        "17c3b38c112ac61c1f0d46555f379f14",
        "90353ed2d3d2cd620347ff246e8fbab6",
        "605bc18f84cd0d6fa2f89306e7b8bbe7",
        "36c7ca4b19f9a52361e9e37acd1d722a",
        "00aac0b66183fdc920b327e838e2c510",
        "760643364617415cf6f398a622815bcb",
        "20cc2fdcba3efbb30c4237a04420481d",
        "6846997e8b58b871cd970b9672f37208",
        "9f1fe8291eaffa6d105a448cf5c205e3",
        "328bab29272628f576e01286c5898f49",
        "bda65668cac4b8b638427dd798d07e4e",
        "dab0a34e303f6ed4b9be9a1bd84022c2",
        "0ac8141e9f120da06c7ec2985c572183",
        "395c9207e88dfae9d449ba23ba08d50f",
        "45d2ed5675ab4afb1bda4f6669a75f69",
        "16023cc31b7a057d494f34aca320968c",
        "a82bc7a70e52d52034b26b7be9915f4f",
        "21b1e6c73377e51c89e8d6b3646f7f7d",
        "87e1adcc0f686e51557a48dec29195ea",
        "4a3c3ff61f28bcdd8ae7bc89c739ffcf",
        "6ebedefb5d39ced092ffe3cf7eb6407e",
        "516d862b2c86b26abe83e717214759ce",
        "41165d4d283041559f14fa857b2668b8",
        "51c8b9eaee7f670e19b5af1c91962ea3",
        "520b2d90b0c5458ba1b9e4239638d643",
        "67e4cfc74854099774d7853c5862ebf9",
        "5268eda2386ec6b4d6731df565c6bee2",
        "1faf125afd8879650e99ae1c046043ea",
        "7c890946e442124662381dfbfd7e8d6c",
        "e990084afbaf6da087b764c025e7ad9d",
        "0c1394161f8865ad7c3bc232c2df1705",
        "3d5f4f256706fb6f27ad21c9a179008a",
        "d965106dcf2f4ba9d501235f8a7994da",
        "514d025bc4a4a2eec77b6063dd54e373",
        "208f736d763c168970abaf3cb1ea3847",
        "bc69710ab4888d8d3509a65ba3d94be0",
        "0e1e8195dd7f0009013cc009d33f7408",
        "fad2fb35e82fbe419484e8b930d53ad9",
        "f6e400ad4b3361b75726c1e0c63ed206",
        "11a5e69893fbab56520de5bf82876e6c",
        "fea759eef11a0cd819aa3bc656e2727c",
        "cb3e090529b65ad9d7036b814fe67bb3",
        "bd9b87d991d17d190644080085afbfb0",
        "8b23aae254f1b993a297b45b7dbcb828",
        "a8b6529b16a3afa8c2c2121cac51ae36",
        "c9b04086d3369c6b62b175b26e7dfa3b",
        "952d76c7eb776471a8f847aaf7be1444",
        "0be55b35743734f50eb30ca0be772455",
        "2c3dc177702e113d7a317049770fd6de",
        "537aafeac4f68b3c9edd7a2a4b69f9cb",
        "f3092444254aa32c7da692f452987a16",
        "183325e88214bb9694a7969fc22ce222",
        "1d7bb1528414bdcab709d5107f766d88",
        "2eae267be1bd32ff073b50f7b654aed2",
        "95e060c139fbd884c156222546efeca0",
        "eb3199c1c0ea80a27030b54b73cf0a8f",
        "865e9455f770eb97a0ee247f2ea1b1ac",
        "2a7849ad155ebae2bf40625c6bb654a3",
        "3dfa8742c223879b407b380f8fa6dc97",
        "47d2eb439d2bc5224e13b0904ab5ce5c",
        "86b140dff315216aa98645f89feac00f",
        "21caceb3a62c434222cdf4913991d761",
        "330efb3ca926ebf810c33f4d56090e10",
        "31dbcd680cfcb9ed3475a3517a9b864a",
        "362af2bb11b58c9e47bcc8a44eb74e8a",
        "438ae193788866155563994784966321",
        "0a478695a4cadfb10900bda102171700",
        "1ae41a25e3059aa207a9502d981b6a69",
        "c5ad2a54ab110455cd425dc3219004cf",
        "c32e453e73a9121c3344a7305b376da1",
        "7eac1f115a9f38294c07f53899f6efa3",
        "73927fa5ac71453b955c6ede24478450",
        "9ba25e3d8fb690ee54f583c8d6df2bf1",
        "69b6e9074b3e8b2edd91c1b3133cb87b",
        "f8945ef09945865d6fd9edfbf00c10c8",
        "8ef7c19026fa438c039b24081a9d80d7",
        "4ad859b0253e3b4677b07a820b8099d2",
        "26eee1689d64ab19a4a8646028d49005",
        "9972a0cd17b9185a01fab25a94e29650",
        "7e83432b2187e6dfb1a5f7073c0ad8b2",
        "331fa1abb51c7489b936e066c2e1b615",
        "82b2a7d34b2521e9c9f06492083a8fb4",
        "909ba7274093075a6b4d1f317c280fae",
        "01b1e184f46bb0533559a1eb234ae2db",
        "e7db7654e5e91a5d01a9acfc0052a592",
        "dce0924f6523d79e4e3b6cf5c3483528",
        "e24e5c166fcf10a44ee37c87b7aa05cf",
        "02706b6b2b9a095e8553d792d25b7f31",
        "b061e49b46f22c3aa2da7e1c44383432",
        "7e5f964587b9d6daedc0af07d0bbb53b",
        "99bfe98f7d55114a1713190155462a3a",
        "01e63d730298c743fa1d7ae278d81259",
        "ffd503c7c057a8d36b74229a5af79f98",
        "dbb4aae8d2f7608647d3bf4f13c5cb1d",
        "46e74202416267a1cfb9e1dbd85618dc",
        "5a99895bfb02306be6e1278026cc969e",
        "ca8365d4f3a8f2afc3bb51665062ba5b",
        "2dd1488c24914cc34cea36a3a9241ca9",
        "a2397c041419034e5ace9ec95e2f5514",
        "d9cb8d0566500c7392bc3eda8cb316d1",
        "adb31284c7afc1c1de5a3335ff4f1130",
        "4ad2b4c78294ce1c7336ff572cd112f6",
        "ba013cd00c998249eda1e1b2efe699c5",
        "b501eac7b41eb53a523673d55847f633",
        "f2d7104209045ca7a1bf9f199a9520f5",
        "0265f9466ecff898146cbf64b1b32986",
        "943974f95a92feeca5982d16dbc0c8e3",
        "91ec8bac2386c410676702e3338550fa",
        "f4b428568687f516df35f656b3be5236",
        "74ac28f89ff1b86adeca096874352957",
        "18f0958944490cab7206975acb899fe8",
        "f243d08b789fb59f2af79762036ad371",
        "fd70f2e22f4afdcbc85dd3a875ec09fb",
        "183e14cc2d4a2867e3a56fcff6647e86",
        "4ebf396d748ec3d460ce312e18bdae49",
        "34680b2b5287b9c3de12837ac2bf7bfa",
        "45e6b8ae0e500555c2f026cb0b736c6c",
        "f395d199ef36203ccb40e4cf19e6b5f9",
        "e330d03457b75ad3d820e0e334cc1112",
        "7ae5db5a818e5a9082ab5787eca3369a",
        "64d9b1a41a1015d4af26c1578996c2f4",
        "b95346f13cb21fbf32dae5fbf13f6ea6",
        "89db0db8dbf4c0d54543e70a5701cbae",
        "8a97995728ceb054bfb93abfe3679d92",
        "dbbc89e0dff14f64313a077e1ddc5e01",
        "4fda06c1b8aea5d3b6d20c2ad7009e79",
        "fa321f27939c7198a12df491b0ac200c",
        "7706613845e2df06b06fe8ac50fb4bb9",
        "b41e27548e306d07aac4c65c45be0e52",
        "e307b875892fde3e40a0f80213559742",
        "fe20397e20a422fce41cb99600458ce4"
    };

    const std::string m_7000 = "386abcdcf0c696342b7c1b8a15085672";
};

TEST_F(Md4Tests, Simple) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Md4Tests, ResetWorks) {
    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_NO_THROW(m_hfun.reset());
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Md4Tests, BasicInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox jumps over the lazy dog", 43));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Md4Tests, ChoppedInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox ", 20));
    EXPECT_NO_THROW(m_hfun.update("jumps o", 7));
    EXPECT_NO_THROW(m_hfun.update("ver the la", 10));
    EXPECT_NO_THROW(m_hfun.update("zy dog", 6));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Md4Tests, Extensive) {
    int i, j;
    for (i = 0; i < m_cmp.size(); i++) {
        EXPECT_NO_THROW(m_hfun.reset());
        for (j = 0; j < i; j++)
            EXPECT_NO_THROW(m_hfun.update("A", 1));
        EXPECT_NO_THROW(m_hfun.finalize());
        EXPECT_EQ(m_hfun.hexdigest(), m_cmp.at(i));
    }
}

TEST_F(Md4Tests, SevenThousandAs) {
    int i;
    for (i = 0; i < 1000; i++)
        EXPECT_NO_THROW(m_hfun.update("AAAAAAA", 7));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_7000);
}

TEST_F(Md4Tests, UpdateAfterFinal) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_THROW(m_hfun.update("Hello", 5), std::invalid_argument);
}

TEST_F(Md4Tests, DigestBeforeFinal) {
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
    EXPECT_NO_THROW(m_hfun.reset());

    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
}
