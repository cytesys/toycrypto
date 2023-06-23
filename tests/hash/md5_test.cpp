#include <gtest/gtest.h>

#include <toycrypto/hash/md5.h>

class Md5Tests : public ::testing::Test {
protected:
    void SetUp() override {
        m_hfun.reset();
    }

    MD5 m_hfun{};

    const std::string m_empty_digest =
        "d41d8cd98f00b204e9800998ecf8427e";
    const std::string m_fox_digest =
        "9e107d9d372bb6826bd81d3542a419d6";

    const std::array<std::string, 134> m_cmp = {
        "d41d8cd98f00b204e9800998ecf8427e",
        "7fc56270e7a70fa81a5935b72eacbe29",
        "3b98e2dffc6cb06a89dcb0d5c60a0206",
        "e1faffb3e614e6c2fba74296962386b7",
        "098890dde069e9abad63f19a0d9e1f32",
        "f6a6263167c92de8644ac998b3c4e4d1",
        "36d04a9d74392c727b1a9bf97a7bcbac",
        "8430894cfeb54a3625f18fe24fce272e",
        "aee9e38cb4d40ec2794542567539b4c8",
        "6c9395cacd317eed2777f669103b7181",
        "16c52c6e8326c071da771e66dc6e9e57",
        "aae9ed2aebd46960a986cfb376bc1eca",
        "02737e4e8c87d7466b623c1f844fdd71",
        "a68c7b41f873e90566acec7c22f89824",
        "74d8c66251bba513d7d317dd47f556ba",
        "409c94b762769ea5fb9384eb9bddf207",
        "d8a73157ce10cd94a91c2079fc9a92c8",
        "1105d53d33874fe294a18ee36398f2dc",
        "9fe125b6680b43a62953d4cc6f4e08bf",
        "7ae4d6728e33ff002bf67a2e5194ccb1",
        "76d36e98f312e98ff908c8c82c8dd623",
        "59f34ff3997b416f4f2dee1c9776c0cd",
        "8b4cc90d421780e7674e2a25db33b770",
        "38079371e04ce549db3e4d69bc96b3ad",
        "c7c6abfa9cb508f7fc178d4045313a94",
        "1995da96cd16a48cebcbc08424f6f945",
        "9894d0235313057edec272848ca193f3",
        "878d9f8dea73b35e1d23570409b0a09d",
        "35ea99843da5ff0639992be381c5b77a",
        "cf5205dc20fb05145e6d1fa08166e94e",
        "a8a7d9c5e31058f15d25f18d7d65404a",
        "d09170db213e1a1fdc5effd49fd34767",
        "5216ddcc58e8dade5256075e77f642da",
        "eeda92ae5deb94f83a420113abf8db3e",
        "c502d08c1b470938c6ad6402d73ffa7c",
        "1745e3f118cb7c3b06917ed035427be0",
        "4f1c2efbe48a8c356719ba8d650eb59a",
        "8ecdaa52efd25a2282474086751be6e8",
        "8a90f4969a8b73f146ea82e698b48399",
        "4cf128e398c559e5a326250b2950b324",
        "a9451e544b3ae4ad6baad228d5a46198",
        "b25f2d814909c3b18113334821cf053c",
        "c99f7d99c916683fe209635da89be182",
        "34e3889bc4a95b9aa5a762b8139a1a17",
        "23005536dba2c412a23bbe1041e007ca",
        "3716e1f619b6157af16ab896055bc53c",
        "e556c822d81f0d60adcb1e9cd79019e8",
        "a005a3b237ec9a6845bb4e12c446269d",
        "7b7d4499eced8ca9011ef849b2527f40",
        "804db6924eef06dfc1deb82374a14357",
        "1e2d1a8f03accd4907d668b183c2f9f0",
        "8fe46666af298bf2c1022a628d73e954",
        "cd82d082cbf9c283698ee3c40d227343",
        "cb921c762cd08f891a14018dbca60c27",
        "de05237f7d3965e0b33351893d23e05e",
        "e38a93ffe074a99b3fed47dfbe37db21",
        "a2f3e2024931bd470555002aa5ccc010",
        "9a7c38569e5a96e3cfbad45fb9ce5209",
        "ef843f60078dd0d52413dd05309f8503",
        "b0b5e976f4e7e61b01f13817aaf7da7e",
        "e009747e74dd24f3274fc71c240921b7",
        "14259830f67657a39cb0bdf5d6bb4e4b",
        "a5446e80abd7c822bf6a154887caea36",
        "5f1c4bb2970471a5c75b7ba1dc9ee3ed",
        "d289a97565bc2d27ac8b8545a5ddba45",
        "162b6d6eb17cd9da55f95f8c73a32dda",
        "263544e5fb8cee117a76710c91873cec",
        "cb856e8bdfb00c240d43441aa7c62e9f",
        "b4ddfbc8ab9013a21c5c8ff3f65537ea",
        "3a7905811de8d12f15f053dacfb075c0",
        "689158e3ab606ff0b6e05b235013ab1f",
        "1495b736f7537831e34a40af06bd5575",
        "24a5ef3682803a062feaadad76dabda8",
        "5b14e2f00f331b4b307ffc10d92ed6b4",
        "96da6c4d2ea3ddf7ebc7d3d725a8656f",
        "164bbc5d4f015d7887ca0547adde6b2a",
        "6691e14925187bf8ff93f50a3907d125",
        "b3c5f33e9d7f3447da289f0920c9d550",
        "3b81e316af4278783279eb7fc5dc407d",
        "dba391088a107c47b058fe1bba0c4d08",
        "d1d9abe750525b2b6c74a5291f52baa7",
        "2929b007945c1478f46b99aa4ae2b0b1",
        "f3f4af90de21614b9ddec57870c70dcc",
        "07b9fcbb87a4921d9c8e58c204ec307b",
        "8b67cbf8dd11b206f0d9bc92972f4be0",
        "e956031d7bfe0e613c86b6d27fd126a0",
        "cf44b8fa68852805934711114e945b47",
        "7ac8012738403ec10f1cbf30c4538353",
        "11b7911a8936476fc51fabb6aebb6e6f",
        "c361ea08682089603bda2a6ef28108ba",
        "a5a8385e26fa709bbf1bbdde6cefb7a1",
        "27fd6842da77a8c92c9804277f5cf3f4",
        "1c338ca7acf975388bc135c75232804f",
        "4af8f15554380d5ce01a1fe072b5f4d7",
        "233909403bee2841400c073fa0c2f0d1",
        "dca320aa35f5a754c369fd31bafa30c7",
        "954792a8ba2f259c097cef263d266adf",
        "e9018e10d68212472a14f1b7ab5f46c2",
        "610e001f0e9a36fc4d31b729921c8ff4",
        "a084962919933d45036aab389119bf39",
        "8adc5937e635f6c9af646f0b23560fae",
        "3c8be50e3861f3186c64d6060d908687",
        "37a4de6f0baffe4b173e4b8952f75a1b",
        "cbbb41907893482c08dea2fc1c936517",
        "090fab9db7d143e890cd871eb0d33182",
        "c76df96f72da0aecc231d3d5976eef6e",
        "fbb107ae7eedfb0db8f50a3c9ae3244b",
        "1dcdd148bffaa57c4f18d5820150dd02",
        "3b7c289ce292384ad3ecce8f7958d83f",
        "51febdeb6539b80db0985f877034655f",
        "96c4c88592557e9f7be67f551bd254af",
        "c910749737f5a2415b09e3e2c441c82f",
        "2ec535edaa45deef6987f8e781631b41",
        "4ae676becc18c2880b8c223690a6ef25",
        "c78af98240c5c01e42847e3a102f509e",
        "951139f259d91ef730b01faeeedf62fd",
        "d65c10650418225b66e3b50bd57ab432",
        "db1004c652c2506f1f3a1f11a46245e0",
        "01cd8992507a5ff1b55c5ebbf0bc0565",
        "4f428c9ec478ab46260c143f95b68bd6",
        "2fc9840470860d0d8e67a2207d15c4c9",
        "edd9f3996bdc04ed8aba723b3a85a953",
        "755fdd01c5ec96e2e1abf97a37dff987",
        "9b573b2e4c4b91558f6afd65262a6fb9",
        "84cec34b0f884f3a5389ec8737c23280",
        "aa4f3dbbaae79e677474d1c89da49fd4",
        "b2dd2bb10ade5f63319ddff03481e50e",
        "8bd9d049efff74b0a4a4fcb2eb563702",
        "af35b0d348e5162036e183339d385b0c",
        "73c804ed1d6216da1c49ea4cded846cc",
        "e79c1023ae890f40ad58c6571364f968",
        "c7f7454a4e442a9dc3d9bcd477524596",
        "99563c345e3333c08ea85f9f0610b9c0",
        "881d406256c11bb563d5c941d97cc894"
    };

    const std::string m_7000 = "44c1c8802177da9b3edbddd7c1ec44e2";
};

TEST_F(Md5Tests, Simple) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Md5Tests, ResetWorks) {
    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_NO_THROW(m_hfun.reset());
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Md5Tests, BasicInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox jumps over the lazy dog", 43));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Md5Tests, ChoppedInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox ", 20));
    EXPECT_NO_THROW(m_hfun.update("jumps o", 7));
    EXPECT_NO_THROW(m_hfun.update("ver the la", 10));
    EXPECT_NO_THROW(m_hfun.update("zy dog", 6));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Md5Tests, Extensive) {
    int i, j;
    for (i = 0; i < m_cmp.size(); i++) {
        EXPECT_NO_THROW(m_hfun.reset());
        for (j = 0; j < i; j++)
            EXPECT_NO_THROW(m_hfun.update("A", 1));
        EXPECT_NO_THROW(m_hfun.finalize());
        EXPECT_EQ(m_hfun.hexdigest(), m_cmp.at(i));
    }
}

TEST_F(Md5Tests, SevenThousandAs) {
    int i;
    for (i = 0; i < 1000; i++)
        EXPECT_NO_THROW(m_hfun.update("AAAAAAA", 7));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_7000);
}

TEST_F(Md5Tests, UpdateAfterFinal) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_THROW(m_hfun.update("Hello", 5), std::invalid_argument);
}

TEST_F(Md5Tests, DigestBeforeFinal) {
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
    EXPECT_NO_THROW(m_hfun.reset());

    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
}
