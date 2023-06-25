#include <gtest/gtest.h>

#include <toycrypto/hash/sha3.h>

class Shake128Tests : public ::testing::Test {
protected:
    void SetUp() override {
        m_hfun.reset();
    }

    SHAKE128 m_hfun{};

    const size_t m_digest_size = 35;

    const std::string m_empty_digest =
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263cb1ee";

    const std::string m_fox_digest =
        "f4202e3c5852f9182a0430fd8144f0a74b95e7417ecae17db0f8cfeed0e3e66eb5585e";

    const std::array<std::string, 134> m_cmp = {
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263cb1ee",
        "a5ba3aeee1525b4ae5439e54cd711f14850251e02c5999a53f61374c0ae089ef905a30",
        "ee0b5458f2aafba112976bd88a4ae4cc3500b9d27e3a2dab8c010eb2fe8f518869b5f7",
        "15e0fe495a05b74f9fd3eaa8a898a623488220dcbf9ba2f12d23d278b7cecfa4a5e4b8",
        "547260c6330814b54770daad5b39c15ad159de955afc13622d9fa7b7d189953674bb09",
        "de13994cda96f534baa32eadc3d06b75a4f4b9fea5e93c062ade9888c9461eb9740263",
        "c71732be9b36e6f065a7df4d1226a63bb249c638f606a3a2d3a9f96e85798fcf4d6f91",
        "4e5b77a5c82f5dbd9277b12865b6f5cdaa8a9d0cdc7d6c12584908096969cf66f02cb4",
        "7563192fc97803aeaca71c4906483fb3c7223c6add5a6e8c58fa1501957be6b21f3a76",
        "5b1df55e38237a059765375af085de6c6aaa4e506382fe92af5a6472aabdfc669abb40",
        "67e4ccf4efd3817b7f51c946d8a905ee078ce80508bff32dc6d2720c6ec97720fa7d13",
        "981341688023048d1fa0e532bbd54a5178ae97399995cfed109c372fbe625b0fffbd36",
        "1bf0b642af7459a35a6fddc51b09fb1c73d0fb488a99c9f6b955ff5899fed892e5e223",
        "696103eb52713cb64f1f5bba4bfc3241d121c6d2a2394258a5c6f9a37c70774ad16170",
        "59a7bbd484e1895ae566e400e0e9c3e6834a949dc70c9c458653ddd1ea35f74d461c29",
        "02d75c3bb94ab6863c06927b1e5679c5a8ea561ea674a482ed86c032e27a0fc6e58a3f",
        "89deb141abda65354f61d93957832c905b007ac6b89e5a49119c6c9412d1e482f0a62b",
        "c825c40ab0fefb4ce883c866185088c0070cee7f147c2058f8b59faf782b74142341a2",
        "f275229824f2dad433e9202df631d59f0e0ab297c7dfe35b98a1079d026f02c8d934ce",
        "688b24b8167adb4b74de74e5fa2e72812fc2299557d35ca3487b1071fa3244bd1396d2",
        "d9b395707b5b3da94ca85a947993aea7e5536462a258b5dc1d039a9bde4fc9ffb60275",
        "7a39a59fea3c1a3125ac550e78117786031e5ddadb0f8640f1a84b3a4b2cdbbf513e1a",
        "984ffc11ba608927a76c67dd307015ce2cbb16e355e2e1a6bfa6bf87faaee76aee17c5",
        "f429944fda9498630abc54546b8facaa2aae23f7527199e6ae0f48600e31ea67dce936",
        "ca3b1710534bb8df876c6cf9c0366000ba1b1a96aaa654d93383e373bbd9fa8c57fab9",
        "754d59ae4aa98312ccda93e01318e6ff3af6a5664876c9362e2907321a24f1ab1c1870",
        "bdbef6bc2869d005c2b66362ae7ab8dc1df4e725f25017dc13f1042e62519d27d54384",
        "d239878af558f160a8d978d8d52ed028fe546c8af705b9c104ee3dfe396fe055a0c6b5",
        "a9372864df9c084a2ab396eae62596eb57c62e47365ffefd89db1d5f3ceb9adeb546c1",
        "2146ef82a0b3a668984ec0a297a83b09f0fcd015bfa0245ea5cb3cfef4ed880b4bee1b",
        "78d8a598d707a8eb3efda7b6bd056beba5a921d6edfad7f168c83d3527b63f9a35b681",
        "587901b75551d492c40666c4cdb6760feabb56179022f88bba35ee9f8f765f6cb64f94",
        "46abe48d810fb351b51c6f42b1978c3d49e934e005a0adf30e1f77013dc7c4ebfd0fb6",
        "8cbf4455801b2d3ffab9c58defafaf078b0cb5d4a4141822e43455963b60867a59ae7e",
        "18f2f12f20254d1729f0dee774d99a7b98094b365186b1a6848e11a00e77b9d5282871",
        "40d5ed020e12bf48a228ad5817fc24652f2122097dd1d264e6af23f927d742530dfa27",
        "ae933543f86ff72bcd0f305e0a9f149ed95e4f36b3ff129b584a28b4da8c6241a4d6c7",
        "e131731c46e121140858aa228ded5e3894e215d5a213620c0edbce444faed4733dac39",
        "e628e495e783c0377e6aeb79bd2d4b706c6e772659abe268aa8fef536c87546d1cbf0e",
        "c2bb36860fb7884d12de4f9dc6704cd00692d15b0a24028b7f3ffd16a1cecf7cc5e33d",
        "d726d94c70f1aff50a0888b2ab5a8c244318c8500e5c8d197914cdae18e047e831f24f",
        "25e85d87972587d16f5c9b2042a959e2cde6175109e0d6905440c5b15607af3dc5059b",
        "4a2151ed5398c4ad91327598695a7d0ff36e73405a14a6b4677d24e1d5d28fdf2ad0ac",
        "1ad5a8414d875dd87f3801746cd9126e07d5472ef7be9d7b9958cb1e845e39e8ce272e",
        "2e3787ccd092353637cd0c9e161cf7d6464923c0d4eb5ebfe55f5373720d9aa3c93a71",
        "09d32a830dfc8a33b2553b9bd16b1258bea41cdcf0e90686e3ff2273fa9d2aff7d6e7c",
        "96cc0754d629bb36a3b0c00e0b7d725889d75720c9ec9aa545c4c500228801dfc39175",
        "c48026fa193b1b6d9691eeb23afa55b1e013b9b379b9c9b84c9c535e1863260f0ac90b",
        "8f35188d0ff75125d4dee700e2040ea5d8965748e8d27f1b338d644afa50fec7d5cbf9",
        "b7cae63044f490e12ca1161a8cb61aefab967a0651fed9b0658b319c5a4e8ba18a0620",
        "6f137c630e7736079034fb63db479a49670824156ec692f2f10806de9f4d206ba8ec10",
        "314cfa625c52529348c0ab8d831798263505337c81d24cbccf554a7c7bf359b0834ac1",
        "6abb5c142e58b6cc2b8f45c6370fffbaf2ec09c7f9d131f435b2b14a4703e55ba85143",
        "3bf5c3d3dfa2930d64decf8d026e1d18cf76005972cad603c1162eedcabc9b164c8359",
        "f5fb0add2a7a312db80570cd6a0e9e6c879351f45c2886566010b1a4883fdc7225067e",
        "05a7c5cd09d17801816e3e65d95c2bf5cf1b8bf33677e6f0951f72ee02314cf12ed04c",
        "bd23db1f6d2bf6e73d5df477c0de3ae6bcbafcd50ab86f2f5908f28191381a0c3315e2",
        "2b44bc8ebe9565d9c16e4aa395daa8ad7648589ff68f4b6548fd1362bb12b7e3fb244c",
        "ac54282fae0d0d02df663873c8a688ea21932f4cab1c87c7183a0b1e78ecce36464ac4",
        "854e585666208bd253a8e334114e4582f96abd3729d16f7407492e8e57c2f09ae31c8f",
        "8ff9bfa14bc98364232e2aa03315912dfa82d559fbc9ffd41c3f5066d56b2a4bd0e25a",
        "1a14c240f8129884bdd458e8409ebe05715efccfd45fe1f21045be251895d8a96cf219",
        "032b5660bea3e9081544dd70973c004baba4ebb44405d19487d8f3d4ac4678a663dc49",
        "c5547d5459174ff08c0e8de0eb61dbf31049ec0f5d1f3cdfa04cdc43172c79dc80eb4b",
        "99fbad19a9a047585bb3d098ecc9f7c5dc024d78385c38bbcaa80fe6c1d2b00f5adaa7",
        "77109c32b0b6f2662b97d688ac5dfb1fe92ba40e3ccf1a0a16f9e896012228ab0920ec",
        "2e6a232a98e75345c708c980d091e3f8009273906c5faa474eae24d52362701405703e",
        "110316d7a71fff764a9cbd9438e153953bed3053b8bdf17d1881813b1bd03efeef39de",
        "b417a86c69e53626a21bb55d2097e6a12f43b16a9a86849d3952dbc0083d2403da1bed",
        "5a52202468a7473c0d7591a5704e6f7525cf1689204ced7e3630123d6482bc33247628",
        "44bd4f8dedb317ab155c778996825ee152917942a19964d242552945d4a57dca1934d1",
        "74a060cc5d0f577254cc44cdf2d1d9f3f27e931322089d9f0595a4b578d9bd4613bc92",
        "1d99cb542d6572adccafa8c3ca1b52c2d523afa572377d4e425dd448b947db6555d937",
        "e7f09fc37e68152223a135897d157df2b99c3aa823358ccd78163de2847df4e390b36d",
        "55225c9cf826209c477cfda41e7000a820c29c76a7398ef8f65ee7ad5249806b2930d4",
        "99bb3bb5cb2e683a314b779a04d2af3dc059a91286c1ab02e63b7956b95e8ccdb1289f",
        "e8ad5024064a4fac5a12ae3d6f209ab0d7a51e02833395fe7796bf09b1f3dbb03fc847",
        "fe9c4e986cf00ace535b745b4165dde4b9223274e2f5c4fbd35a4fe742a6a29406645d",
        "97b95a04ef416cb1e13f7515a73c718b83e6271069d86ba5fb1672ae935753e7dd26d9",
        "9684980fe51eac88b574e3b5fd06900fdc69961f640dca05e1c99c86c90e173adaaf06",
        "dffb1c81ed0f824cde5f87b1db2136197344b177bd71e7102615afc6947f96e03851c5",
        "4d0290a60ec3f9c8752fa0eae158c284a72564d0f9bf97bd5f1354b3a165dbb69144ca",
        "0fe4bfa36005fdf2c71a0453f1b4e6ab98257c53510a48a4983ddbb034063935b2e3dd",
        "8ed6affdd59207b096148e572c825eeae8a31c59889c507de5908132a16917e4963325",
        "a874c6c4a8be3db27a446f672d30af2102c6d4892e2023e1db6decf83c2fb1f8f1de76",
        "f563b30942a83cfd7968950bf06f58561190b6d1de65dab12aac4310e65b51ca7f6082",
        "ac37378f398822b96b09e26710548bd35ce0991e21417964702804cffdf7187e65870a",
        "f9704d74532e3d9315d1100008ea97f537d7d15d21d13cdeecd8a7df1d6719bfd11f9b",
        "9d297a5bdbd1e9ccb9ba69421e9ff1d94f631378e740744261fb70cfb6ad1292604f33",
        "1c02e2ba13b2daa0ea077f90443f3496334fec6cb67e838c319b984d4fc142231b838c",
        "e5a42bd101cf56e7a795d42b7cc620bc184ed8b41d53d3e818a1599a76e61654fb595d",
        "d4405e16d1a163fb5ea802abe0219ec661959ecb055562b4e6ac5c6425f0d9b7a47191",
        "445642954bca587032139fb485513f4aff48636ddccb23e5c23fd2cd378ddbed196723",
        "558e57b24c92a8d1aa404ef75a2a3eaddc56212be38c15ea6ced7a475727997f540339",
        "54a92e7e79ba3d239fdf99f6384ab9aff093309e0c5ad3c9ddf4f977968e9c81945f6d",
        "07800810ecd85e07d58f478e080ae3244dff312801a7a0c7e0666b1611bafe2aa0661c",
        "0020ccd4d7da3ab581aee662db6d100e5e9aef2c0fb64934bca0f7a25fba5c9f1b77cb",
        "f5ea3e2d3e578a05b95d98720ce02def67904c75b78723cd71d86cf7ef2e351e9c06a2",
        "764f56ea96f87497b04423cf68aedda5467a5fef46d9ca95d9248a79c10842bd0e14c9",
        "397fd28a76e2ea0e2a95770ed85267c4cb72b7da2fdcb73aa2e6bf77e1d914a15b768c",
        "572c49808b16659e0ff733875c7e7ab7e0f55a3631372e40962203395affe0a3e232ff",
        "377e0321ff1415102c1e667a6161752eda8dea708b116e2b2428981041cf2849fcb5f0",
        "acd41d8ebf82fb41d782b75795287383b92f80ffad0e993be4668b381c9363f28da792",
        "70f2320920630aab6a3d173783a053f9a72315783d2b0bf97749edc96792987ed53777",
        "5a8f743fb622aa0115f40e0ba2b0a6cfed51869bd7601aa8368541ffbf6856beee7b18",
        "4f093a45cfa13b7dbbb6f494d1f3234df33ab6f9bdfbe78fcf0d0ae9572a4db678fd68",
        "6eb8380f177df9125fb726ee50e2be5e46f1b4b80bef141e568f5a47ae65e3dafccd06",
        "150eb243a97103943cfce8c5cdcd16baa203d6d70a5b8600f47966bcf4270f1ba98037",
        "0688847a4d66982a8226de811a0cc7ff76b11b97e6537ffc2ad061db874ecc3fd5253f",
        "97abdd876d64c7991fe7901f2b5bb85aa57d44925845311bc39afce10ddd326a0cc23a",
        "c68fa134a66771a92981d01bbe6749b30f9a32d48a1ac7862077b5da64dbf5abb94724",
        "83afe5978dee8ab9bd7cdebc611c7dcf69851d398d8e9ac1c68aad7f46b3a723556d1e",
        "df43f9ccdfbc72d15c82df30ed763062d85fe4048749e077069730ef4f9ae4517bdf7e",
        "971381c9dce973ed9721353e1566d53fe0ef9b5822befef3c84187b892d9896db9e1e7",
        "33d49fd1cd95ceb77e5eabfed8f853920c8b47adf3b07112fdf8d477609bb6afb2b831",
        "a6835015cd9b778283126418d86a37e3ad30fe5d1b18cf25ffa77797e120f7750f6027",
        "bd35c4566f34fd02704cccc3f3ebcc5fd7ef11b62b3772a8ebde38bf7d831985f230ff",
        "9161820a8e13d1f12869b0ccf308e748eea1cc0a6df8921847a9b17f0b91ee8db46e67",
        "e5666878cae5866df70080ab890217f941807d55c634ce810f876a14b03d8ec9ca3148",
        "9938cd8c0e8c7630dd10255ac0bf381ba0e00725da4856a7b4d8ea81df2090f7078752",
        "3c7247fcbe248a6f6e569d2a7f90a3740d9768a7a9c71c4e2393ff76568dcfbc46f953",
        "1af08cacdd912d5be3e7b1f9ad5bf35af2ab7aff357fcde8e1e8df1575397ff08f00fc",
        "563527452789b9c63e82ca23d383d041674f655dc9e343723ca920813bfd22474da3b8",
        "a6c2edd3e464c147f689d0250de3e5c711534a6dd8434448dd1da2cd729025206c4187",
        "71e9c56bafea616bb7642e34281ca5f6ea39f075bd27445607efbb02f6732a7f2e4dbb",
        "9a6113d6c7aebae7eb1df962538c91728fa12eb0fa3b6093def95327932fcdabee7d4f",
        "a155dae285b0fb79835a8c399dbc5e9f36572468b5d69a81051b966aa71062fd6b4659",
        "d0b991e23b2d1e61b79b2de374518da544954e7f768d8d8d4e2b301326f90b63a2a4d9",
        "57b72345190523ccd8cf8c861c60ffb04a2cb9cc712724f496ef8c593952261d568f99",
        "5a0d4b5d4bda2ae026d05dbaadfc8b7c0c61cec50b8c9d446afeb11779e36beac10ffb",
        "380e1a3a3e59786891623e77871466c9e8a589ea1d8b587bd484a9ff91c89d805bd1ed",
        "903172f8ed40e816a95e4ef3b3483077f2d8d7dc384166a4e83063dcf55ad1f2b13ef2",
        "e28849d7734c07725c447d55f4f10e10ad57263b7ac6de3c93e31c12b811adc2e7cd20",
        "a0d8ef13fda9a5cf37ee46a0e62a5e2f3b3f54d9a63dbe89710f183a834f61c4d8d98c"
    };

    const std::string m_7000 =
        "6efa97861c6ba6cc8a527797f9f3d06b28f534c87166cf57884c1862ed01550aa483bd";
};

TEST_F(Shake128Tests, Simple) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(m_digest_size), m_empty_digest);
}

TEST_F(Shake128Tests, ResetWorks) {
    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_NO_THROW(m_hfun.reset());
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(m_digest_size), m_empty_digest);
}

TEST_F(Shake128Tests, BasicInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox jumps over the lazy dog", 43));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(m_digest_size), m_fox_digest);
}

TEST_F(Shake128Tests, ChoppedInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox ", 20));
    EXPECT_NO_THROW(m_hfun.update("jumps o", 7));
    EXPECT_NO_THROW(m_hfun.update("ver the la", 10));
    EXPECT_NO_THROW(m_hfun.update("zy dog", 6));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(m_digest_size), m_fox_digest);
}

TEST_F(Shake128Tests, Extensive) {
    int i, j;
    for (i = 0; i < m_cmp.size(); i++) {
        EXPECT_NO_THROW(m_hfun.reset());
        for (j = 0; j < i; j++)
            EXPECT_NO_THROW(m_hfun.update("A", 1));
        EXPECT_NO_THROW(m_hfun.finalize());
        EXPECT_EQ(m_hfun.hexdigest(m_digest_size), m_cmp.at(i));
    }
}

TEST_F(Shake128Tests, SevenThousandAs) {
    int i;
    for (i = 0; i < 1000; i++)
        EXPECT_NO_THROW(m_hfun.update("AAAAAAA", 7));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(m_digest_size), m_7000);
}

TEST_F(Shake128Tests, UpdateAfterFinal) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_THROW(m_hfun.update("Hello", 5), std::invalid_argument);
}

TEST_F(Shake128Tests, DigestBeforeFinal) {
    EXPECT_THROW(m_hfun.hexdigest(m_digest_size), std::invalid_argument);
    EXPECT_NO_THROW(m_hfun.reset());

    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_THROW(m_hfun.hexdigest(m_digest_size), std::invalid_argument);
}
