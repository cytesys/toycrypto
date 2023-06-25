#include <gtest/gtest.h>

#include <toycrypto/hash/sha3.h>

class Sha3_224Tests : public ::testing::Test {
protected:
    void SetUp() override {
        m_hfun.reset();
    }

    SHA3_224 m_hfun{};

    const std::string m_empty_digest =
        "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7";

    const std::string m_fox_digest =
        "d15dadceaa4d5d7bb3b48f446421d542e08ad8887305e28d58335795";

    const std::array<std::string, 134> m_cmp = {
        "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
        "97e2f98c0938943ab1a18a1721a04dff922ecc1ad14d4bbf905c02ca",
        "a16bae681b15eb93b0abdfbe91d403cd3d2deb8b5034eda3d75b5545",
        "c09d5af7d9a021c484041218f3c3787fd4274b64ffd012edca0fe55b",
        "5accd6cfeec028803453ddd46aed0f9281336fc2215484d0f9110336",
        "3af7c71f280b8dbba309562874657094cef8850c642c8a701b125284",
        "a21541f4a8a2a69d4c2e633723a3ed5ecaecee3df05982b229195f64",
        "efe60918d203eb247e7e546bc3c126e4e2f7d6710af9e5479bc70d1c",
        "337eb5ca90bf94f1bac3281cacf87214cbb441208e5b8e1ec6fcb2ad",
        "aa085f9c57144365871c2469f631695da03c0683d03fe2c7c61453fe",
        "860e405c4336b7902dd76f90f67318a65a509632a90732dc768e7879",
        "03c4e7a21fc61d39c426acbf63f846c4e59bf413ab32ed51516755b5",
        "e35bad7493b0b2feca10d92c4f9c73ede12f997280528ebc9ed2355f",
        "c3c8b6e88d05f025db27cf35504296b429742333a1438db9dfa18580",
        "d4abd3584870497a63b7751cc0d2bdd5dc3e15bd0b46813f2fb42484",
        "fc5d872aa7106d8f41da3f86725bb761274d4cad4463880fc8f4e9a3",
        "445215f965178aa7bb7dda56286fe51e45b6e4724dd6a33d4872057c",
        "321df30631672f784bcd95a0a64a1e743b53bf9f5fc70a31d449ff97",
        "2883feb3469e3f4f92a98b988252cfbbe0584ccb4160b9c860498ad1",
        "1f361095d273f3b99e30a02d025894e631b35b2bb606e945ee6e0a48",
        "21250e853f1cd59d681c79089180ec9f157625ba61d0faeb2172b0c5",
        "1b8f54c6d91d9bcc0b7eb8bcb24df71d6058db0ccf8ff47f5e9822fc",
        "0de3819707bf846cda9f06b571ef3e7204e9b28fee45282cfc3a6cbb",
        "510a09de2426907831a8bd449bda521a21755dd5a6533de1f9405c84",
        "31e45461fde3d5894120183050897b96bcf28f39547570e04482b519",
        "c558157f8c3e49b46521eb0a5b02143e4637468e2886efc62bbd6382",
        "ac4cbd543304baf05c923366b18136f418d65ead0d495590c61de5df",
        "8c1f3516ca3acaf04cc16873c67ad653eaa96ed9246a4edfd00f9b20",
        "ff47ff0b830e90786b16199aab67d4a3b0a03af433e3f6f6c2e464e3",
        "3c8aa5656f6c95cb97d6e14cbcf470d484aa890af5f15c234e24bfe0",
        "5a012089fe2186ae1bedf7065aacc6eb0313cb841aed01530f38e774",
        "6770b855467e3f67b369465b3d06291833cfe74d5abf91a075d0ecd5",
        "2909db30a39a1a43529f787d6823b368318d9660d3f3f6bd237cf5d4",
        "fba62181aabaeb783f52495fd339eefc53d830f0d1f472618a976351",
        "e501ea2ce7321a02e600b97e209d303ae2cd8efa2b8f9c0de4fff164",
        "175e4a3b0922ff45a59a0b51c726a2ef06721f708a19a524b34fe916",
        "48f3ac95106db6f608a63f31b8f42fa42a54b27fb392f25bbfaf478f",
        "0b92631b9832f1c77b27cdd4136b261e874d8be2f846ec06f8f2bf6c",
        "e66db2db1a1d47df83540157d32d173a5714a9eb959cccb6ff4da943",
        "14f5598584df839d01d95e5f5cf46ad327bdaef88d4c28edeade9a57",
        "11620b49742b21f96789d0f858b5953a823748f44276a3a6fbe83fbb",
        "3cf4281e9a0cfc1997ad381dce0034aafa11a668c97b29475b0352da",
        "4021e923caccef58a9b685f76d725b0574d222dfedab9f244f8da4d5",
        "98d300ca5e168bee9d4066ecd9fc786602505b7681b28f83a9e3e26f",
        "872701f0ecc7475720ed701023c1afa52bebd5655573c0fab75c7366",
        "18322e54a235eea6856cf12e89b475b5b9e5e937e77ccaee2afc3731",
        "3545ae47e98033aa099072a09ace8cdfeb56b31cf3a2a68d01533983",
        "dbcec2e6a125345f7e724a0c7289270280e8c1c3a11a3367bfe9e0d2",
        "a4567658c866218b6d74709a8148f7b767be189e153418e6713dfbd7",
        "7807cd7ca7b2a2788fac2df3ca898f0989c43872d3eb4fd38758ccbd",
        "32f328fb0f5fcc807145edf682fbb61aa20cf06327031534c48b3d48",
        "b519cc46c5611289ab69203aa64e8f708e148cd97985584d78560ea9",
        "386c6178ae42c75a94de3c0aafd1269118966b0736df05de11140433",
        "475780683fbb7b6058f9d0026c23510144acaae6a179e7308e6147d4",
        "9214fced4e7bff959cbec528dec8af37f80a8739123ad8af0554fa2e",
        "ec341b09b03c02d581d026181a4ad079ba8e37c308141e20ae48b858",
        "e8956a2e575555fdbd49afcfad107e63b0443ba519c3dc0de561c937",
        "f6a864a6208566227d0e2249e0e356ec9b95ab9c7d1780b3ea1c8015",
        "97dcefd86665dbca04be336e87f542b2535ae951f005d4422211a898",
        "9aab704b99b79d03d4f8cee07e5060c3406d07e5a91d61920c2c1672",
        "ead0fdfeceb8bc2d0d4ce18ae806493a6a22b7974a341dc9f50406cb",
        "6dd9cd07ba2985547c60987e6d3246466bb47caaf2d5bd77f2bbde14",
        "6dcbfe4de4a51825ec497f5fb8083ccbde5510f097f7e5b5d4600885",
        "4f134080f1db2245c1bf95818fbd64123afe6b830abb77a97dd7ea9a",
        "b4857e221c02748ff90487df74b006216e432bca32771282cd3d524d",
        "3f1d98ed43df1399da4b6253736f6137f35ad1be03b1410d76abba55",
        "3f3b44da2e39063045d39211d333e5d4c749a4699ce5a9a99091d212",
        "c64e94e2a96202ed978f77b1802ce556da983df0dd572a0e97d3e080",
        "64522857b64252a10284ec456fd6aae96ef6656caa2861b542492789",
        "74197e740013a67b70a058b2002691ac004d60cd9919fd138d76b4d7",
        "80e4650d39bc2e34412a51b7178c0bf4876c967bfe03169960f4c598",
        "87e603d0cbeaa2d232f2c68d5c34fc5adde3afd8ea3a0da76c61fac1",
        "dbb19a46efbc8060b88951d2ec1510ef9c30837eea44c0201d8e9b4d",
        "ce8f0a4cd5365e47bc08eb78a883df3d525e7130f454c1a5e14a3ab3",
        "72f2a3a8067d2fa94e6b01a7f6a597bf6841cb03214b91f3d9466f35",
        "ecd2bc34bf09844d8b8e2a7a575f2bb248443e4d460290a27febe553",
        "95e1b81465ea76a9c4033ccbccdf6fdae52ad83171cc3f8bfdc4d50c",
        "b6e2d7c09ccd63aac78cefe9f97b3fb95b57f990520f95124eac8f77",
        "0bd48f20d7c6765b286ec32beedeb103244a27dd23c6c3f285b08fe2",
        "409072eb380bbe3eefaf139cf137703706f3c8a849229bfe0feb1f12",
        "4c8ba3d6e3a62674aac5aa6323bfed1f2c322b32916d9771d01acdf3",
        "36db274c9b7cc6c2c8b5b859337bebf68bac00aa075e83c95e167f6a",
        "0b349638adda9b24ceee7b615c261dbd23e9de53f68c2faeb2eeba5e",
        "efb2f6b0eb4c9ba2ee882e99069b2804e55c8b4f8f56c3c11aec2749",
        "94171569eb0027457726f3bdea8b1b576c8535b8145b9f882f2b4cda",
        "648afb532ef4de359a74292a214c5260332ee164273020d3137f4428",
        "110d387eea6c30f91bcf908397f90bb701c74ca5cbe84d40461625a5",
        "71a5d21348a221426424b1c67d4e04fbb7625473597fc71a3f28780c",
        "6801cac74695d51cc671a8290dc0e149178d61359848e86b7142b0fb",
        "ea6ff60863bd70d3986c0cb642a2bdc3581ff936ce4774c7fe0bd355",
        "0ea98278276ce86b3dc5ad07218bd4766d56454c4f1689f4537cc326",
        "b2262c0211d06a834572d7dbbfb9185e60bc431f695051744b01080d",
        "688ba896a327fdb39af88e87d63eac2ec7bb874c1f20e8a4deba55c0",
        "107251a67654f8ba81028d14d647ac7f32a97e4b16886e7c69d4f366",
        "ba74928e459de7a81927dbf44c5966a0cf0dafc8981ac06d95c52708",
        "39cbbce102a6c1b76e8f030984761d185ac2c43748e480aa4ea4f819",
        "8474c04c45a91a60f720d72e718a0dda7ab28ce1bde5af63fb0d8f06",
        "bdd608cea61ee987db46bc4a8457244290b32f4cf6571255314e4176",
        "309158bc288672f3b18c50134dd3e64b319d1e85398244c95b26776f",
        "e7699c415b403996d9b9fed8bc6aa5862348767d16d24e56765bb6ba",
        "54b068d525e2959aebe79d170c611153b8763f5fcf30cdf14bedf4e1",
        "51534fe68c89137f13e9c91e93778a7ca76725f5a6da0764c1871135",
        "cc5fac3b28b8a6721fecd29b5b8cc49dd6014a34a3fb36ea67f48f8d",
        "a16b876d7f5623acc944c82c61909916bcbc7157be522d1cc74ca764",
        "75f8ad4d50065a0e69f907cd286fb02ce6499c28bdcf56e1a913770c",
        "4a941b013e987938f52aac550ecc5a8a9bffa995e28be2954364a656",
        "64ae1677169c41386c8d3246f8d4522604875ed3ba827f288b14541b",
        "651b885695d9dd275c7a59125c0f2e0aecf14215616e91ebed8d8e4e",
        "292ab4c79955818184c386d4fd90a991ba31f20e87970acbec084996",
        "4fcd0d2b99a47d550739cd164d8e1d519760c530188799b6016c12be",
        "286788b05b1d4bd7cb3fc8a68dd998c0092ad2f66c984313ea827776",
        "f1b639cb314cbeda80ca161480d1f946ac4f2d8df517f25a13609da4",
        "bcde0a934aa4120c30428895e33570ad9054079f0b93382323d70339",
        "98c1cd5740706f59d3aae4d09a45778006a363fb1516725a18d0ef81",
        "457998656bfa0e0fb60ddd02110003a340293fb8807b75a35132442e",
        "a321a4bc14d7dadaae5ed1e069ab8ec0e4dbc60f2e43d60a91e97725",
        "f108a822c45ef68e97a0b32b02b5d4265114c2fcc4ce59fc8ebed8e3",
        "701ac43eb62e5a08ce0dec84f85226ea8a99b0e87ac510503cdf2b81",
        "5efe47c88252869289e063aedf6718e882110d098d198147f6a56e6c",
        "444cc0384a796bc45f2c80fc7bd14183e9f92930e637d6b6b0f2b99a",
        "60a095164b73ab9cdac6b88660b50f9626d10215b47d301bbacfa631",
        "6dca28057366e4431c1f6d9a75f125eb27349c97ce38f97d31c4ced1",
        "3b0f97d92d6f86450dc3a0631b2f360ec54a0882d82f0c27892bd442",
        "f67c09b6069e6bffa697d948887ca72d6e34bdc9a5c1df2ca676bbbe",
        "0fe024e7ab6df131abe8bb94402ef197cc12651a2e8abbbf94acf852",
        "877ff0725891f3256fd92377197554454abbc2f206ccd21646ca390d",
        "c6164b4c17ebd16d5a917e64631b8eee1afa1e4426e357a843645c0c",
        "f90c43c713a11de1ff970b75b8d250b42c1b8034155c07af74065f84",
        "b3be58ed0556c3e0002c778b3b4fa270137c8395d86442cdb6d38837",
        "6e8dd9d6f2d6d48876c2685f2ce0e5768a3ad940c10187e7f82c5e8e",
        "244d0471cdba61c7c5e99c97093c8b9d3b1a5cc4814f595306580289",
        "c81a37976a0d1d03146ca2843044cd95f129c77a5a84854a0e758acd",
        "6a83da65d16bd70cdb832b72022117ba7dd560c674c1c846b096c983",
        "2918451e0676a9b7ed94a15d4b6551a0330f40fc4a504f211be4ee25"
    };

    const std::string m_7000 =
        "09640ce11825c10c3bc1fa5c32fff19fbc46baeb85a3a018a625c5aa";
};

TEST_F(Sha3_224Tests, Simple) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Sha3_224Tests, ResetWorks) {
    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_NO_THROW(m_hfun.reset());
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Sha3_224Tests, BasicInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox jumps over the lazy dog", 43));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Sha3_224Tests, ChoppedInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox ", 20));
    EXPECT_NO_THROW(m_hfun.update("jumps o", 7));
    EXPECT_NO_THROW(m_hfun.update("ver the la", 10));
    EXPECT_NO_THROW(m_hfun.update("zy dog", 6));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Sha3_224Tests, Extensive) {
    int i, j;
    for (i = 0; i < m_cmp.size(); i++) {
        EXPECT_NO_THROW(m_hfun.reset());
        for (j = 0; j < i; j++)
            EXPECT_NO_THROW(m_hfun.update("A", 1));
        EXPECT_NO_THROW(m_hfun.finalize());
        EXPECT_EQ(m_hfun.hexdigest(), m_cmp.at(i));
    }
}

TEST_F(Sha3_224Tests, SevenThousandAs) {
    int i;
    for (i = 0; i < 1000; i++)
        EXPECT_NO_THROW(m_hfun.update("AAAAAAA", 7));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_7000);
}

TEST_F(Sha3_224Tests, UpdateAfterFinal) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_THROW(m_hfun.update("Hello", 5), std::invalid_argument);
}

TEST_F(Sha3_224Tests, DigestBeforeFinal) {
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
    EXPECT_NO_THROW(m_hfun.reset());

    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
}
