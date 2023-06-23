#include <gtest/gtest.h>

#include <toycrypto/hash/md2.h>

class Md2Tests : public ::testing::Test {
protected:
    void SetUp() override {
        m_hfun.reset();
    }

    MD2 m_hfun{};

    const std::string m_empty_digest =
        "8350e5a3e24c153df2275c9f80692773";

    const std::string m_fox_digest =
        "03d85a0d629d2c442e987525319fc471";

    const std::array<std::string, 134> m_cmp = {
        "8350e5a3e24c153df2275c9f80692773",
        "08e2a3810d8426443ecacaf47aeedd17",
        "0ee215a0f91e8a67e9ea52f151151913",
        "8788c1729761fdad983b830f04b19e86",
        "3fc0aab8f5715786a02393555aa9393c",
        "fbdac6a6de18ad721677ce7a7be82027",
        "a4fef60ab8541b1c49e81d0a38ba7846",
        "6529442d22860c366a133ac2d344b672",
        "3eb560552e3d2b8e4936d2c0e93bc78e",
        "e3ea5cc73f82f98a0a9954e6bec77c04",
        "be2f1daac01fee2f2c59565866093dad",
        "63a926c0582ef0148ef493d16133317b",
        "3778b6d4495d3cf39013f6f8cd3955fb",
        "22fa4bb1477989640847e88c0ea59302",
        "264c063f7bb0c7ad688f1f58e96f5eb2",
        "5ae29b614bbfcf235f13c6d72f5c9a86",
        "5a895c425750a7eaad4028bbe720909f",
        "7a60ee08b0123ba4ab0c5046ae505f78",
        "1f4e49f2d107d173d9d059687eca5c82",
        "e74b4cac388e129348767eb2f6e64e02",
        "ad563a4de96ebc309b8258cc1a4792e0",
        "a51092a86e7d2b9b28e5ab4310ee31a0",
        "d9da71511185457cf9033e833e74872e",
        "5018ac74aef63ed5446942f26acf3943",
        "3f6d8782c3c557dd1ca1900746a99b94",
        "df5f64c8e5e667619abd5372cde915ab",
        "55b746cd48b1e4449b2ec35ea4de4978",
        "e67c3dedc6cdaa64fbd909f376fd48f4",
        "aed117d27f79dd79cdfa8109d0d3a5c4",
        "51a85de43c07dfdace8d6fee5b22bfd8",
        "a60bc7876e924b7142fc44ff379e23f9",
        "ee892eb73ce8b96cb3d84df15ae44ad0",
        "976c703d4d9c692e7eb2e7fe3406e851",
        "b28d3219c78c0e6820ec4804c73c598d",
        "07ee7ca2af438d072e5be4da63cd2a7a",
        "612bd8e0ddae733324a7d319eafdab12",
        "eca5d3e3372535abb9baf5280abe865a",
        "d81b70d98ac87587e90de2ce4997d5c8",
        "72f24504d900dc52839f486dc74347b1",
        "7b8cd20e8763abe90d1f25263092e8b7",
        "8d8da792b91909f29c996933062951b3",
        "3e0b940af4bf5721bcc48004cd06cca8",
        "e34a3ef35b6dd20fe7c54c9006c373ff",
        "57596e4011079d69e826ee8d24cf0663",
        "0d8ec4af2ea95b869551d52701db462d",
        "217df86064ac64eebda2633f603c859f",
        "7be1ba7d6f136c8cf5d69d18ece32fae",
        "99b9d5c1cd5c5975b4afc407caa9964f",
        "8baf0baf68b8c45534de1435589017a0",
        "7e3f11b54784e13e136e85a34dba2278",
        "ceefe33e640451f688de6bab4285b3bb",
        "e2bf8459ae1c9385100770770699f853",
        "995fd4a889e93e1925f034ca2bec71cb",
        "bc659244a363761ed1cb2b3397cb31c3",
        "a01446c6334eec4a65ebb7ea41b976a8",
        "bc9a2b9d6c253dc4a01f51779ad324f0",
        "2d416b30f66eebcecccee3072aba0066",
        "6fd9c8f5119fa5149232494862b26e14",
        "b7ab2aa40b35d52fd89bdc97bd343b4e",
        "c7e42206183ada8b35937b2d69f0b2e1",
        "316a38220e5f6d286006b0522e2763ec",
        "a57a7a7a8ad95e8e654119b986bf1792",
        "e19b30a2245ab9ddb0aaa749932333a5",
        "fade3c776659274e476b6ae3fd95d641",
        "288786ca38a2be4cc173e6235f627bde",
        "d052794615a38e5388794c77c27c814c",
        "6ae19b5dd79fd345b51a82ab3ae43a74",
        "ee026b637d21f59fa7c982ee249cb18b",
        "cc5e3fbc5ef5fbc34007a32c97135813",
        "7733e21cecb11aa0e72b459b3cc686a4",
        "dad12254db5599781e826be35414455f",
        "a5d80205984a8909022b9b7209364f69",
        "df1418b74dc421380cea35ddbce13b81",
        "fee7f168676815eba211cbb41fa5a121",
        "db34664a6440b401c4c9aaacb7450a23",
        "59bb2c2a3b8efceccd49716561bed581",
        "312a4d0330428830bf2636f5b43f7cf3",
        "3f8b71e38cdef2419f5aa27ea3332bc0",
        "0009531c1a24ba9b9b5ab44c5b748ed3",
        "b9e54d57b1224878c6e3209a0eed3ff1",
        "19448bd7d0456049c4169e5e57a8b3c3",
        "bbc545cd4b6d5ef6d0b4e829e3da023b",
        "06bb5cb8dc20e2dba90a5f0d06e6770f",
        "121972abc96eb17008a59dd996ceb63e",
        "cfe5ac55fc3a37e023fa2e3ace6ae9bc",
        "a64e11c187d4be828f4548cbd182fe9e",
        "b1b2942b859b061fbeac02b44834d619",
        "9f6f155f5e67b61246e6b302148dc5a7",
        "ec22de3029d160b0fe30846cacf9ad10",
        "9cea25fb0b3e7c8d5b5dcf2c4e30260e",
        "981b7a5f00411849b2dd3c18d9783a31",
        "5f720dff67e7de9f719893ea1333d1c1",
        "894f910ecf9b20be26a01b8655c2a9db",
        "8e41760649bae6bdf4073afee7fe4911",
        "95d326175cade1e2b44bf5ee6f423467",
        "61dedb16d71194e555761d76d5cb9214",
        "2ea9f94d058212a3a9a80d57925dcf79",
        "d30ceb0b3863be2224a561f95a9ab647",
        "0bb859063bdb76e166cd34d737dd992e",
        "9844ea2c606b57ac2423ae604cabfa87",
        "7574d299e7fa00bc0d7fd24ac2b34149",
        "db836d983a940354e72a11309dd020d4",
        "f034b23eb8d0ccf2926d203f65c6adc8",
        "ae240097331bf7a815744e9557fb0e1a",
        "4e1b3955305f41ed25df61c17ac68a77",
        "f47df3c0c73d73156f8876097ac913c8",
        "959f00e428d766457f5f7844b8eb9458",
        "506c4f5a201bc0c50d15f2800ca382ba",
        "4ca3a44f4e2d2d4034d22385bd59839e",
        "8fc2b694ff526f658364cee266b66b03",
        "17b19f8f625ec530affb47680e8bedc6",
        "d9b1ed79cb02b4c55b284b86c2a86afe",
        "b54ed11169a2c894b6f2eed8557ddc0c",
        "d086cd6d6cbc1ba697d740c4d0f52814",
        "1cfb253277a5cb9fc7cd3bdb1de04017",
        "2436a78a2ea8e9317a592acbdd047950",
        "63b2c6ac46ec2900f0c9f81b6c2f80a2",
        "07f984122d88554a7fa930c2d82caf11",
        "710c3af9127679552c723b44f325ba3a",
        "30183ac93d7fe1454d594c56a5949638",
        "498b1c1738973ca0256868c109e7f770",
        "1c50807aee5938db8fe12259172b10af",
        "1fb8c54bf4fa4dbaec6bd55fe2421258",
        "398b8dd7275152583bddc3fd414d25ae",
        "020590485162b1cf07a162b3b23a3fc7",
        "f3aebc61ed421efe0f273a3c1c4b1bc8",
        "6557900aa497fa78e31fdf4a3380b174",
        "053066868bffc095930f39b3abace3ec",
        "420d45645b36cde9de8c8b6cd5de9de9",
        "c4097410620fa735d87fe01527b72f46",
        "344ba5562da69318360f7eb3c004596a",
        "60a658a4ea957a4e214cc513af57c82d",
        "b3e79358c91b2e659c55fab7f14cb259",
        "c30558e8487a1cce2fbbd29019d4f378"
    };

    const std::string m_7000 =
        "98f206c3c2cbbbef1b0101f7a968d4be";
};

TEST_F(Md2Tests, Simple) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Md2Tests, ResetWorks) {
    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_NO_THROW(m_hfun.reset());
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Md2Tests, BasicInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox jumps over the lazy dog", 43));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Md2Tests, ChoppedInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox ", 20));
    EXPECT_NO_THROW(m_hfun.update("jumps o", 7));
    EXPECT_NO_THROW(m_hfun.update("ver the la", 10));
    EXPECT_NO_THROW(m_hfun.update("zy dog", 6));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Md2Tests, Extensive) {
    int i, j;
    for (i = 0; i < m_cmp.size(); i++) {
        EXPECT_NO_THROW(m_hfun.reset());
        for (j = 0; j < i; j++)
            EXPECT_NO_THROW(m_hfun.update("A", 1));
        EXPECT_NO_THROW(m_hfun.finalize());
        EXPECT_EQ(m_hfun.hexdigest(), m_cmp.at(i));
    }
}

TEST_F(Md2Tests, SevenThousandAs) {
    int i;
    for (i = 0; i < 1000; i++)
        EXPECT_NO_THROW(m_hfun.update("AAAAAAA", 7));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_7000);
}

TEST_F(Md2Tests, UpdateAfterFinal) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_THROW(m_hfun.update("Hello", 5), std::invalid_argument);
}

TEST_F(Md2Tests, DigestBeforeFinal) {
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
    EXPECT_NO_THROW(m_hfun.reset());

    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
}
