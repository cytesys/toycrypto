#include <gtest/gtest.h>

#include <toycrypto/hash/blake2.h>

class Blake2sKeyedTests : public ::testing::Test {
protected:
    void SetUp() override {
        m_hfun.reset();
        m_hfun.set_key(m_key.c_str(), m_key.length());
    }

    BLAKE2s m_hfun{256};

    const std::string m_key = "supersecret";

    const std::string m_empty_digest =
        "552d7f729017fb53ff5306ad5ede2d4a4ba00841994f1ce2bd66a6edb37d8432";

    const std::string m_fox_digest =
        "0a5f5bc1c84388f8e7784f094f919b0b43f8abc344ff355dd12d677b0a229677";

    const std::array<std::string, 134> m_cmp = {
        "552d7f729017fb53ff5306ad5ede2d4a4ba00841994f1ce2bd66a6edb37d8432",
        "bd58944affd92d38e9b8be598f30325e8d5f6525f6e209cfa6cbc3658726a818",
        "93a3b3a16fa96c623bde94f3816e74172dad3269c3a7c7a0742471f8a57bb385",
        "ea9449381662df6bdcebc46e1fb5ce9983a61e949552c241e70ba02e02507b17",
        "16fe6ece4e2ad8730cbd2ac839d9b60e35c0aab42796c0ab6fb9d7e7d342976e",
        "f89439a9154942ef2d13b852b6a7497ff27ee25d47bf7217804b88f851a92851",
        "73e126b5b95bb0842cfd1e68e1cd4c67cbe8aea57f9de75f16d7758eae1eb77a",
        "bf0dda9911a48084f7805676cbf3edfcb138fb73519d76e390df460782e27ebf",
        "571f9ea5e348023a68babcb84ac7ca69099bbf4296eab99ade32af8fca32a825",
        "6c6eb1971a0a5388960c3c9998b69aa42ff78b21dfbb2622339c8ec1f4067e08",
        "2a871eb5056ecced7b254aa4ac3fec6530800bb303858331bb80c792ba2ff709",
        "d317f47f175451ff0a08be18f08b01f1171c6e1819e82ea2cac6b45170ebc90f",
        "1099450f57cc186c518207ddf371e8de987f894cc031084b16a41fb270024eaa",
        "e222d4d6f047e0df1f748d31904b54be2fec970bb5673aef28585eb418e9f7c3",
        "360930607ae7fee0dff5aab77d24101cf27f496e65800ce4b979f19d41d74f41",
        "14de1495b00fe80861f7d62586a293ab7e66a36601ed80d19cca52ee64bcf74e",
        "65c6f2aa8e2e7163bd21744dbc0631e4bf80d10cbfe1250ccac053a8641db374",
        "4c912ab010f814650c1b97960da3f54cf728110d9c161d28333a7c9564f99fa1",
        "5592ae306b6225011051d9215ce713276a6a3eb4098e14bd612834519800f2fc",
        "df2640b3670dbfecedfe4307ec3a0632d3c279a0336f7c614efc0c1f19a3a2f3",
        "936d1d54edfcdf5ca489af02704d3bd4c7dffc5e6b925dd55a9e81db5b8f469f",
        "5ad5f00948e52f4e0a310d3bd4ed04109d210f05f14ba09a71a72993ac2c1dca",
        "4afc1aeb9a12912f05317f70b70e4baefedb9221a83a5578b2e93cde0c1bcb09",
        "e364e5b9af65619473c0f77b5d3099e2ce5f756dc7a0503df6f8be4563534d59",
        "e2e44d71a1977c6141d61d7c6e8a38e3bfbb80c02145dbc8a04f1b8e0cbcef1e",
        "7699a0050cd7465cf4c177753e056edd4cb441d08b988f9aa3ae7f528ef19e3c",
        "5a134da94a446e469266d0cef1c1fe3e19d0d098790d0c8ba44b068c229e1e07",
        "efe64c3adc907a4a850143abe7984a58f738d1c175fa6f9d614da72cae783a68",
        "52a4a359c13a55b3c1a93e8b11bfad0ccc3d1c9c78439a70d0a364f7e0000cf6",
        "6edb9867a0303b41122cb101e060cce9e31187929fdb3d20348855b4d88c0405",
        "23cfe614d2c5a0256a5bf515f73af5f2aa48c4b016704a19f1832c3202d4c2f6",
        "4d05daa78765d84d2fdbb15ed83cf21251e5a4e6f15168dd851f9362f7f38254",
        "7f3436bc036aae73ae20cd48b09b82e5bae7efa43fcf8e77e443399b44a53a1f",
        "3264fa015e8b7539cab73adce3c4b11d207889f2f1a802076a937b66d5086fc6",
        "870fd65d0eb74ab60a2ab481142e0b224eb84f48875758f71605ba5e5dc78888",
        "fc046827f68aecfbf399d6b561e37cb710bdcadb6199b6476f7bb3ce9bd1ffe1",
        "9f331782c7b12e31985246e6ece263972ff1870e8b2e25ac92b159d1a5133d9f",
        "0263ff76051cbbb79d402b7bdcdcb738cc543cd1bd6655fd324ddd12a203a95f",
        "72b57fb6b33228adc956a95c976b1d35800640d13ac4399dc6e6baed2e856f3d",
        "928711fba95cfff29f001bba3e72401b5a68cd377389779847551866e5d8de76",
        "75c1f3bafcb55f012c27c5e02c3a1ba195f64ad76caefb4b16c71dfe59884c39",
        "cdff150eb5bed030215f182c493901280527e8111cea24538e0b33c2bf09aecf",
        "80f9fe48c7f1013317958cbd1dbd3a6903d270d0559d6ef9c03a0ee222f119a4",
        "be6f238f919389cddf6ceceb4e842de16294360df864fb8045973cde79be1a69",
        "b2e9ce739cb0b49f158e89c00638bcdd476d3bc9a7216e9955d387c5ebe1b41a",
        "a35e339ab6e47670f9f272bd804d1db6f4df82dcf8ba702af470c9d0bffc1ea6",
        "3b0a21b41cfe6e9a1fd2aee260bb9470b4be98f393f852a8f110d80841d346ce",
        "8c53c0eefb49d0c60aab74497c3cd5601babdfcd92fe92d2413a5e627cf66b5f",
        "67eca28fe3085022ced6e561b90bcf2e1a3b0ea7b806c408cad3f5f05dd016b2",
        "1693815503d4ff0357e1112de314586af605cfd65a0269e71bbd4ece0a63407b",
        "a0992ef966dbf2f2605bbd941ed4d575ec9d999363f45bcc3fcf1fd77b0b2fe4",
        "3d3c8246ae3611f6172ab0ae5a83fbed04854500632d2712f0d44c8b8cfa868b",
        "dfff5921822dbafdc78c6ccd45d9915ac198657319024a16c89f5205bf02bde8",
        "e13f986ce0cc734796a2bae9352b4c4f87d3933e0522d80976fef2a8fd121b4c",
        "cfa4e6b8500ea0c38eb1a4e7dcbea8a15f59d3989e0eb25fe6bb214ff984fa81",
        "c37d689c4cfb5562806fef3afb39c93f7c660e630aea1fc6fa73f67a41c7d561",
        "354080fd8def1885f191b1f3f254b32433ecf306a0730af0e6fd3cc6adf1f5fb",
        "a5ec29213a37886f4b3ebd72af864dcb3f358fe2a8ca7673eb5763b5dba9e9ad",
        "3e4068899b98c52f0a49339141dd883c2f0e51e100308b765a2bff9dd23f8eab",
        "9f00e5f6bac0b1e487ca358df1dccf3144c242b887f0a1bfc8ef8bd4c231442e",
        "933fc739097508400bbfb16f184864c3601e25243a0556659ddd95378a3ee177",
        "5c766e5b5f2aa71f36c1613068ee415e70bdb71c0f410519e3856056f785d6ca",
        "b3244738954770b356639b954842e5ffefe4c2f968480474318c947bbf97103c",
        "6e206bc6608bbd917311b82852a392687127b3a6a8be1ee1af6901f945b86d1f",
        "5803353b43911ba929ce8f22de1d5b7f315934b086b3deda843ac3ac830347f3",
        "f39c76fbedc699bb097ef5c790b1756a87a1ce5a85138fc978de0fd9f389d56c",
        "ea23ec8f2e10a52b6729f1b8fce9881e8c6ca7c0523e0f3802a1941f0a714723",
        "f1796001a24a56dfad1e5acfb6d2e6f60c668f8d8eba90f2fe4e849f78e561dd",
        "54ae320efdeccdba780e6f0debddcd47faec242a8458094f103e1ab1ff9bee92",
        "1b33c9194110c56767d7d7cede3590024d5f9d2d52723c2c22dbd24324e65000",
        "f75cf2a813547a1c4a7291f2458fdd89293171d17f9037409dad0b3be38b2727",
        "c89bc1439f4ff246c2fbbe0acc9f7f6bde5edfd86a0731d965b35ba3f47db6a4",
        "a6c0ef136c49f9c49ec5f9b1e2ac48fa1cc2d9d97baad659014d551ccd0e6063",
        "51a1e3aacb610cdae958cd30b658e0038dba017cb6208b9211575add063358a4",
        "a74effbe57e277dfdb1ca4376ec0af6582fb36bc5cea521a7567a1d1f1791ebd",
        "39f2a9dcd4da14ad76aeb003825550ee5ba03afd8abf6b4ba846e4d7b8a8e1be",
        "7441c0e11e0faf10898f65c35fd1b7447393820ab0893e61db434647c359c247",
        "6e8004a031648c13b9aacf847724bb2e1d5198f56bb3e04ad5632d31c4612b81",
        "f252cc031a2737f9ae660a21f465e2f6cffd07d1ad2c91d2f8b8c3b8e66ce780",
        "b0eda5e26d95c005520bfdfde5e43568fbc4608f27e2b6d81e34ee89879b6cec",
        "d304840b5d11a1b2b94691d7421b90008f052cdafd579ba4475821579dfa868d",
        "113b1f9d0387164d46c6c196db8d9aac044e6c1ede62e8a2661a47793a02ef89",
        "8ccc5b8a38381216013efa3a2f6e38c202befed66e72cddac57feb6954b4be6f",
        "51d423109a66b54b836e9f4dd68df95c70afd12bb72ab66a209cd98448962053",
        "e127ed5ba15eb832744f9c6f6da3937d5f9dd9f6045d3f4ed9196030940457c1",
        "e90a036c23bc414538a3bf7bfe408f7f2c023d18fe7fbff4a323463e2bd61c51",
        "cda5479ab4dcb1a3fe9baaa481bcdee9ed13d20f59303e102bebbc918fcd460a",
        "7668a04153bdd20f79eb42d397e018a4bf270a41db8336c9af195853b75b470e",
        "ede820ada5b18bf9d945dcaa89992fa86a2efcb27eeb61b1b73e2d9e83a99f57",
        "e080c7974a7e44d8335f5154be9d9d38155a00115fb846e57e009e18ae024b11",
        "6bd5bfc8cd4a3d86112e78433c66b1aa5fe4f3d26f1f6137ec06438117e645f4",
        "985813df749affc20c84ea30c5e2ca1931e6f11f8351523821826065a55286a4",
        "b89579f76f2bc3b516ac90dbb6172e843e0d53ad95d2203870a07d6e9b16928f",
        "71e58be9311d4fb80398639255d3cfa854218290750f9782b388a50c26b92208",
        "b381c7a4354fd6074e45a24f1614048bffb70731116657601ee3548bfb272e72",
        "9d37dd933bd5947988e9018369d33f5756b1595313cd878efcb01c753bdc5b6e",
        "dbc422ae97abf6ac7ffb6150aefb9a214d14f06c14319242d883123c159dffeb",
        "f1fc62f6a8407a32eaa04c34820c31e1fa26b6a6bd0f2e1cdb95b14ab3e0ad69",
        "f87a6e43cb9cf6e21bd2bc54848627d5dae6d3310e0cb73c4924da33fb41af40",
        "c3c96d14fe258b0f94e20733a21d36e93821b3ec40ec737c4e364134940441d9",
        "be8955817f75b9d04ad4407a2b1a4af340077aa9a11a67a8e57a51738cddd7ba",
        "a6cab48e99b0407f0fe0a1057b0c933ccef00112bc8081021689e97470f6eb13",
        "c2ff84d6140553f932f3905535473d7da562b79bfc8f3e2d049c8f288a3d4524",
        "df3e6d04f0c5924a7627806c2d6f70afdafe92f58befce40943ad0042d04cda5",
        "aba1aa9fbe9aa45d900a030721983d9b36e12f087cc8e1a83df780c027b9eb7b",
        "db13c3c119ecc02c39be990c63e9d5d136d1fa0622c004aa930ed1ed2ab6d23a",
        "3d32581e384387ef0267588c20cd81832b418f9b969a3d39d0d49fa0266bad50",
        "81399e82c1b4ae4a666e32aa93db28b3fa61ae738689d78d0f676067904f5c3e",
        "9f4354286f8a5b84a845b66ac5fca7b415f8b07b55f7394bba99f40a27c7de10",
        "34750da0b0f84d8a2921fbc9ed89350f131da40b2e42b9dedaea1544a31921d2",
        "ec9ee42dd9bf520ddad90b0358c7e589d416ea9aba2342dc7f08d81172a3a8d1",
        "923bae670bbe3adde6246fd09eda9e35c3292cb5a2ffe77454af140d568d4e3d",
        "4594fdcf32690fb006e2964d3e274c200ceb2cc50169fa5eca81754919566745",
        "e47dd0652f57e8d93d170e62dcc3f4cfa552752fee12e81b73b934819e5bbd0c",
        "ad9fd24576b14aaff2a07436ddf660212068a3b4aff801efecebb34d044b2b0f",
        "9bb88bd4f7f08b7b27cdac4c360581aebf22f2533320085ca094764a7ae88f34",
        "8ddc5626c5306cb8437c4a1e0367ca30afaad21df5a5f3cddb5195cedb9e6a6a",
        "3a8f6e3b7a30d05de6929e74fef8cd0826562cfed88fac8ebbc19cc6aa48cc4f",
        "5d7142491437f890fd2551d74d5104678f4863ee227e88b9f79afafd9d3403b9",
        "70f9dc7153548cd27db68e8b9c6725183dd66f366933fdb1e74401d6676af0cd",
        "e41bf4108a8c6288296a51bb40110a66b5fb7ba3f721de2785767b2df180c27c",
        "1cebcf29f5ae21779766de8e35f8dcb74af10816fdb6b0e9cea061ca3ab2b398",
        "3a89b15f69fb37718bc25e4f7d8237136219f33aac08a0b033d162a99d177fb1",
        "3a2817ea4b3bc37e3cea5bd3d9c4104b0ddb89ee1163c1475d46d760649a68e5",
        "352d9b995ebed89825d4e29c9c545310b69e8acb7dec4e15924e980be602c01f",
        "d7585d28c835296c64ac7cf27677f079853f119f69f6abc2d267b2055c7e1bb6",
        "eb6eddf6d9949ac71c7095fe207ea2fc6e1f9f0501c82b8a57bf7305028f1af2",
        "e5b968b49cbfccc11064c6537e811807b47acde40b86320d09d9309889f1d7c1",
        "fbe1a2111d2af144ec5e264ba54d029c34e2d3f566c726044ff411d876463f6b",
        "fdd4c67a478747e20c35baefb0bba8c40efacf8a94ec3b26a4f5bf5cae64e8bc",
        "96c7795b02752603e3d1aad6e676431f4fd9562b912166749c9e211c3fc9cd7b",
        "60c3784a5c124e626f9873605ae761461c14a4254040061ac044090d0e3d343b",
        "838eb79a9c0a8c93fc6e744631f88250114209177ca92bc2703188b3dd7a6d69",
        "5bb90437938a2cf26c36637ff3c640cb4373dfaca21d3012437e6b8d3af14063"
    };

    const std::string m_7000 =
        "c5d0809f791fb7306bf54b7b2fd89e01f6c2a3b12e8505daead3d3897f837a90";
};

TEST_F(Blake2sKeyedTests, Simple) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Blake2sKeyedTests, ResetWorks) {
    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_NO_THROW(m_hfun.reset());
    EXPECT_NO_THROW(m_hfun.set_key(m_key.c_str(), m_key.length()));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Blake2sKeyedTests, BasicInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox jumps over the lazy dog", 43));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Blake2sKeyedTests, ChoppedInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox ", 20));
    EXPECT_NO_THROW(m_hfun.update("jumps o", 7));
    EXPECT_NO_THROW(m_hfun.update("ver the la", 10));
    EXPECT_NO_THROW(m_hfun.update("zy dog", 6));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Blake2sKeyedTests, Extensive) {
    int i, j;
    for (i = 0; i < m_cmp.size(); i++) {
        EXPECT_NO_THROW(m_hfun.reset());
        EXPECT_NO_THROW(m_hfun.set_key(m_key.c_str(), m_key.length()));
        for (j = 0; j < i; j++)
            EXPECT_NO_THROW(m_hfun.update("A", 1));
        EXPECT_NO_THROW(m_hfun.finalize());
        EXPECT_EQ(m_hfun.hexdigest(), m_cmp.at(i));
    }
}

TEST_F(Blake2sKeyedTests, SevenThousandAs) {
    int i;
    for (i = 0; i < 1000; i++)
        EXPECT_NO_THROW(m_hfun.update("AAAAAAA", 7));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_7000);
}

TEST_F(Blake2sKeyedTests, UpdateAfterFinal) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_THROW(m_hfun.update("Hello", 5), std::invalid_argument);
}

TEST_F(Blake2sKeyedTests, DigestBeforeFinal) {
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
    EXPECT_NO_THROW(m_hfun.reset());

    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
}
