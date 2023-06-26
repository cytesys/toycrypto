#include <gtest/gtest.h>

#include <toycrypto/hash/blake.h>

class Blake256SaltedTests : public ::testing::Test {
protected:
    void SetUp() override {
        m_hfun.reset();
        m_hfun.add_salt(m_salt.c_str(), m_salt.length());
    }

    BLAKE256 m_hfun{};

    std::string m_salt = "whatever";

    const std::string m_empty_digest =
        "d70b604d1372444aed53f04cc7e828f1f4e82f3ae7714f603fbf8f436796dddf";

    const std::string m_fox_digest =
        "59b8eb96972b9f48ffa7d8310cda8a85d12e62b7673907923c6a5f89d5ccfb3b";

    const std::array<std::string, 134> m_cmp = {
        "d70b604d1372444aed53f04cc7e828f1f4e82f3ae7714f603fbf8f436796dddf",
        "9cd34825b8b438ac27be9058872e99240d33e8c3d714f2f13d67be9f19a968c3",
        "4505ebd319f12034bd1f7200ca499449152b3d251c46e456d4927727ffdb0f7e",
        "5a551ee1963a56f3c4193e3bd927fcab8e367024fb8f79012055b799b1988d1f",
        "aab29b7faea4a818ca198b0209e3a7ca9d9bd03aa7d67900aa9789c1d34fe850",
        "60a15e4f2a4c9b7a20837a9f8a7ece7077a71e71967d8d9de1cb848ba15fe598",
        "2708780737ccf8317e90ad934cce4e351ed22ea1c456afb9dba1e2f2cd81226c",
        "f59a70d4c77c282a1d0ba4214e8857099094f0f03076b1c674c1eabbd2e62398",
        "8fa77171e07196e6752212ce96699ea66829e0673be17afc289ee328916090c1",
        "a50bec68f3dcdc776a0462cbf6a5827c92b427e2b95e9e7dd17d1880ab545ef3",
        "f5a3a2e0d7f5ca5da092d50a3368e67fcbffb45353eb5ba21dbebd4022bf5f89",
        "54358f14b469c086e363517b9b6784cd822c7ce9076c909444ec7de70d3389e8",
        "984f534a88fed15849263b1d1f984064dbf86a74e2dd66c0326b37736f15be00",
        "6e0325411fe2fbe5f620f0cf5df7d9744da938c43b7621c0b761947ff422731a",
        "3b9ac9f68314293317a07313d98545fcb71871c80e16c5c161fd3261508fac72",
        "01d7f6d837fdf4615de70c5592af7194cb45cd1822480e23dc79d186520337cf",
        "7296f1c830e3f9b8c346b5cab58bdd06dad2a78d77ec42886561178ea68ad876",
        "28f9448aae90bae1262a891361497d92bf161677767f3024bca25966d5ab8489",
        "2cc2e16c4044d05887462515fe9aa56b27f12d9314a88a8a92e2cf85ce1e59bb",
        "7b395f7b51817d0035b4c022d4fb472fbc1e683bc75deaa2fd273461c42d6b89",
        "69417c52dc2a51d14d034969abec9047b686aea7a6e3c4068ace1b1146e0e6f4",
        "bb44d4984bf537097385f022b0b52991d9a83a219731b79fce8230b975b111c0",
        "160214e4e78a2736a3e86bd9dadb9c2754279699eb44ee6f87cdb557602172ba",
        "444a6a3ee8c3360f2dce96efab16d50b4d73ac6d5e0e18580a91779a58ccc341",
        "8351865798e9e382456ebba517a5733b4463688d4a3225b3e2055089da2992a3",
        "8eb02614d8fadbaba4f475907ae416bbc2d4fd4062ff8b9535b7c0b7dd1545d4",
        "17055d69a55b0ad6057aa0143899ab448cc921f1db32d3142b62f78ecd72e31a",
        "09d9fc515ed8de00c2ed1e16a418428acf445d70b8bdef737270c6f9d42655f7",
        "9d693b8ecbbfff44d6c8ae205d33da18c1ac4411e3c65e1ab1022f1f346ed021",
        "c4892e7357a4134c82d8af33989c1dd7ee6f41a6f0d1256910785981505d3d7f",
        "988cfcd2639a19ea3319ab01fdbec83708f9916529f10d69cc51f3d98084274f",
        "89890127397c2bd2923033a50d389237b02e449b673528491c3d239b80982f91",
        "0a17efc5efdaf387f2b7f6f35837555997d5c789d10cfd6ae578c9088cd5ce15",
        "ea31b7fe7ac3b457789aa28d2cfc494866e3639dd35dbf87fe523bc7ecee85e9",
        "f3be23b750b6d57e0eba918c64496fa2e23d2b90cff747e9a8c04091fb15818f",
        "1639c2f928e6f4ace8f6db8b76845cc3d7227a0361427233da0bc6d52cf05dbc",
        "43bb1a978905c2c3a424fb20f1ff00b74b3f7e1b6f878abffa35fd8ea6c230d1",
        "6a9e1488c094149d504ae34aed0872af465883a71980cca75d072a88d4662dcf",
        "6ffd9df5408ce6fdc05efee72d9be468c9827b0fae64e3c7538eafe9c7d6f77e",
        "e837baf72c28cf8c6fbd403ac5c2802a4eae0ea16ca2aa08b20ea5a4f3ee2010",
        "a921262d74a3fbc2b29a479342411f8ab11339542a9d5bba16741f644fb65e86",
        "0a6649baf199d54cc49195f4e32c8adf329538b60c24bceb940feeca8ef7e16d",
        "e6ee408df4d8c8a6d4d7229d61653be6abf141d55b227477c48e71c1c0ba35c9",
        "6d46fc095e214f784d122506a1d2e64c33a248f653aa4deaf2abe792c484e9eb",
        "40ada1982bf6cad13d0327ff3d2e911006d4630461273908f9a42087e6622bc6",
        "c5570b3ebccf0278885a806501c822ae171d2dd7c70320c7f2029c60caa111e1",
        "7eeeba1916083f2a2742149ba9556b743faa96e4f72c0aa674595436a0547f73",
        "245156bc8875b21036aa44028a19d8b7f2ec53dc444d599da0ebab69e4ad3067",
        "259922960dc2c1716b10db42217a0fa36a4a8037aab759835f09d5c684db73c9",
        "c6a2ce61aec6c726e2d5d6c294ef312aa8d8797f744a23ccae544185b678425e",
        "664e34f3bf1abee1a09717900ad6d4356c88807e8539a56a54eb3ed26e3604cf",
        "f859c740999bb3e295b7b96c9a532b939f60698f72d877db8443d15bef109e0b",
        "7eda6c85fb4a94e50b1f8091c4ee3170f7371266774722ff16d859f0a11c0df3",
        "139c6b2ed346635bb2ea27b6e7228b8e359f51f2175b90640d1408da0654a3bd",
        "ab8caf0db16e58212e9e263bded2d16845bb71e31c6fc1c90ed7cd6a53c9eb03",
        "4c07517136e0ff99548a813d186c510295a7a8037651fe9338ba8b65f5fb4035",
        "57084e93cc860dd81ca1ac5b707e8c4938f76c44929da8a27f3b4147cfc25ee7",
        "b89502e6638458e636066260ba4eb3ebe0fd064bc9255778de159b527cbc93f7",
        "3ff780d92626962833976b47a497ee6d4ddf16c222de932d320bc53e5988905d",
        "eb781be91ebc2a48aef653c5dcf55d9140fa025b1c3b676d4e1276198a13460b",
        "a55fa6aae9b3be2d50552b4bc0c402b0d63604dc7b205b53b9f8a33deb44dd01",
        "c0b01f576f44a29364a16f870a1330af3d66e2102c17fb36222ce7b22d1459d8",
        "5156d2225b1edb7b56feccd3995b149b80f892315e6d03f4a9a46b2903503061",
        "80bbbeede3efaa9efb48dc6d620539840f154191e179e4fa3da296541dffef9f",
        "9fe48aafcd7ed50bf227b5bccb372d1fc6e077d89c9e8b4af938cf5daa51256c",
        "a63bff036235372afd91a4b61ec6b87b5931ae3f8f72af686d95f17dc0228481",
        "76d75b1ad6100cf436ed437be4ea9a2806a0f26746ab56771d75d7085378650e",
        "f7884137c198f9df23ea3b92ada917a1da1ca8f91bba2f9cb623579cca77f785",
        "f2453996b97c882f02ec0579eb4d45201a62ec16f17e00520d89b04e8fb03eb4",
        "631c82906e8b82ad890e053937d410d0e95150e6a8e6407bd440f6c502ff6866",
        "27ffb847a7e1f95df3bcd722df807215ce44ddab85d954cedb9ffc2ac0fcf090",
        "66e65e30fd66c24b8e6a5c600f7e2c2fe884f0281c38e378b2c495334050ba26",
        "ff28f1bb4285f6836440d1991a9497c28c8dae3c9b26f2ec90128cdc835cdf50",
        "9f99b046a5eb64f08bc928b016c8dd8339e72cb3092d18c915c3918a1eeb1f6b",
        "6b65650a7de166422b99eb8f17eb5657f44d17e68dd5399b52e491af56e7c55d",
        "795ef970451833c64ed4013e3643ca62248a8fc15687f2b66222349d15c52b13",
        "6960c539100d1c9c61d253070da5af8b376c4027bb97810f2e1471b4b121f242",
        "34319fdf522adec71a9b99ffc54823a8a2d3a681fbd5e1a39c8eeaff9be1970b",
        "9ea48db051b9028c5bb7f8f0f0ceccaf317f0004f7e5bb79b6ff04f08687a992",
        "6337e063a275d4a8ddb11b68f3fe75de58ef52d0672642e151b9024231443e30",
        "e9dd591236abc3fc9a2a35ffd956bcd55183835cd13692633967d7502d5498fd",
        "612651e148783855d3e62ba4d36b49ea7d20b593eaf77a14ae327bbf72437f7c",
        "b024f45756fbaf4f6e4af805d18dca757398d678622168bdda1be70d0af14589",
        "574008e984c32e2b6ba7871e30c1b65ae7ec8cd90a5e4dcfc2f2e3e5d1941bb7",
        "39eaae9a637d5486f9b588ccf4935072861a68b7516ef1bae34bef6feea9b353",
        "4d5534a7722b2c5bed627ce975bbc22eab1f703003d34e3bc7467280a6cdc490",
        "85926b53b6650bfefa90558229afa30e4031a6b3172a6a1df35165ce70744497",
        "a619935d6f820fabe57630a44d22c0298fdccced3ecfe74d7be56403d3c66a4b",
        "d8189268a7f98d4d47574f7c94f7801b7144e4dfd8a3c3f497c6f4e320bf9152",
        "e8461e4255fcd54386825e8015bebf9d874125b703b25d66da8d3f7a27839ab6",
        "4801d3dfe49f4491efe55d6afb592dce5f7f2ade35fd769b74d2bbdcfdd7e37d",
        "47291b45259cca79e8e0d57dd47af62757cf49da2e2fe47da5de71a0086ae132",
        "90911bf96562abcbc6eed12cac777dadd43219125f9f120a9433563e85f78d7d",
        "0f9aa5559d8ba4b19bbbb800da55b14e0e932e0da8b3f21331be1c2444b33db4",
        "f029d26c2fa9e4b59d4aef1e8a5d46597f6057436107c751858168e577014ff1",
        "76564d9b4115d0929efcb1de3925e85b621e231e2f61c0d3dc6e9e60bf50068e",
        "abd480c2aab559bc4ac6719b306fe8caefc77815a1e8953cc6161813d742f110",
        "cf5953ac04251a4479cea72153192c180324dee64ae72fca2e85a0185c0c5ea4",
        "948fcc0e68f5e98326f923494f16bce1e251ef8a206b6feda1d11f33fddd685d",
        "0a5c69d32dd3cb4e8310d16c4e07b0eb362776da5e9f5c0a98e61b98c7d53377",
        "d5f869d05ca779cd858458079ad58dd6ff68f7321818d719587b40d7a273beee",
        "f14e60812fc076f75709f575c9b38118c03878ce3676925e7427b682a53fd892",
        "b8ded197adde7ca89198bf095367a21d72c68686aeca38153f8c354881c1ce96",
        "7097885df2cc116e7ce8a6297e1ff6b998f296e95051e6738284d46946355bc6",
        "ecf23039b2a409f236189a0a511fae8365bba8272f40cb1d3ebbeb756385a7b6",
        "db740b0ea1b2213e320242e0daded8065cff09313bd62831342cb1f902548688",
        "8f0e41c90828c20d71e18485eb8552b7a0cbc5a1706c2a91669370e8bc55a817",
        "d291153b4c53d28f50b85a01c699749fc9a9be91bbdd538f0f71fd36d90fd4b1",
        "d5fd48b76edac3c9f1c122ffd581ea43c3081ff98243a9574780d61704096dfe",
        "c11209bfc2697960967d63890e45e04e511afa7145660ccd9d5ebab340499a04",
        "b8e414fe7ae3e525fef0a00ab08794ebad90f98a90cb968eb2b220492bf9f0d1",
        "fb6a9ffe253ce6456886bc554064c1429da1c8c29ddf7b7657929a6bb9fbc34b",
        "95890e3f609227615050309e1cfde70512a2d74e7592ec21dbea0169dd11b32d",
        "92e3ac17ec5856ce72e60f26643ca7270591829c82311809e6d02a0876841f24",
        "095692142ac31a843695f76e9b881887ed9b5acd3545746b1540384a14fdabfc",
        "c22fe81e9770a75535b5c2d86b3176570e134ec95c5ca87ad15180aeb874e3fd",
        "c77d57cbe06308df26eee04c11c8f5bf17083d188d3bbbf36f724a0ea62064ff",
        "766241ab0e444af424b2d29d29ff9b3600cc6e9135fdd57945243500a0ece9a6",
        "e456741dd3cdc65596b871dd6e71d407896f02dc43d326ee7c97648906f7d41a",
        "aeb27813ed44993de0085777b17189933b2bd36908915cbbc9ae91ee0289b8cf",
        "9b18c225a0919d4baca635b83b14a8a115bff765d3461bdf2e626e184163f8d0",
        "a5da113ec4cd1e2ea2a796bf07fca0edc02909e8bef817e86737bc8c55e256f7",
        "7a677f63d4bf73a6c0d9c8b6c3dab122df8d96b47053783bffc95611ab7c563a",
        "fae707f8a5e91e71241bce7e3ba8678a97d49cbc20a2aebd832ad16e147a6393",
        "e1ab23811f63c6a184cf31f8f880a57702b36c7ab13e2b364a838f1ebb0db8b5",
        "ee97684b796a6533c7e09f8b708f8a8fa44b53fb0c788db73e371aad5fca9553",
        "5d3dd4b6de46fc9ef32e30df9da79e9fd8f13ce908263bba464800b26e15d445",
        "f160df62f94d4e9729fe47fee5c06b2b947fa3171f6c83f9eff5f3e0b3362464",
        "038292e8be77473c45786c3a70f1f10654e75bf7cb3d1a0de488e7c8c10b8b01",
        "69db8428d0582438f400ca0ef3ea2d9604c0ec1e1bdbaff8b850e07effc29f1a",
        "aa14eb524bbd23ba65a5552b9e9c08cc9678b20d1a544eb20a599884bed2c65c",
        "8e843a33eefc49d64ad6e2f8d52cfe47ea7416db64a176157822354eb2420c56",
        "b2de1fdaee9f048a08d26b920dc9d702b6f0d04c3d930107bf1ce2af3ac1891a",
        "f8ed3d71fa39ab968765ac5da6a846b8d5b3814d56028be5d60efab1e5174eb9"
    };

    const std::string m_7000 =
        "ad9ee4f246aff172e80eebef7ab0be01a19105ce8bf9551dfc7fa258be650ffd";
};

TEST_F(Blake256SaltedTests, Simple) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Blake256SaltedTests, ResetWorks) {
    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_NO_THROW(m_hfun.reset());
    EXPECT_NO_THROW(m_hfun.add_salt(m_salt.c_str(), m_salt.length()));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Blake256SaltedTests, BasicInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox jumps over the lazy dog", 43));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Blake256SaltedTests, ChoppedInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox ", 20));
    EXPECT_NO_THROW(m_hfun.update("jumps o", 7));
    EXPECT_NO_THROW(m_hfun.update("ver the la", 10));
    EXPECT_NO_THROW(m_hfun.update("zy dog", 6));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Blake256SaltedTests, Extensive) {
    int i, j;
    for (i = 0; i < m_cmp.size(); i++) {
        EXPECT_NO_THROW(m_hfun.reset());
        EXPECT_NO_THROW(m_hfun.add_salt(m_salt.c_str(), m_salt.length()));
        for (j = 0; j < i; j++)
            EXPECT_NO_THROW(m_hfun.update("A", 1));
        EXPECT_NO_THROW(m_hfun.finalize());
        EXPECT_EQ(m_hfun.hexdigest(), m_cmp.at(i));
    }
}

TEST_F(Blake256SaltedTests, SevenThousandAs) {
    int i;
    for (i = 0; i < 1000; i++)
        EXPECT_NO_THROW(m_hfun.update("AAAAAAA", 7));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_7000);
}

TEST_F(Blake256SaltedTests, UpdateAfterFinal) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_THROW(m_hfun.update("Hello", 5), std::invalid_argument);
}

TEST_F(Blake256SaltedTests, DigestBeforeFinal) {
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
    EXPECT_NO_THROW(m_hfun.reset());

    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
}
