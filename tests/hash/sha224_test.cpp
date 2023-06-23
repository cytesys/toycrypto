#include <gtest/gtest.h>

#include <toycrypto/hash/sha2.h>

class Sha224Tests : public ::testing::Test {
protected:
    void SetUp() override {
        m_hfun.reset();
    }

    SHA224 m_hfun{};

    const std::string m_empty_digest =
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f";

    const std::string m_fox_digest =
        "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525";

    const std::array<std::string, 134> m_cmp = {
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
        "5cfe2cddbb9940fb4d8505e25ea77e763a0077693dbb01b1a6aa94f2",
        "9030ed3056d813b9cc718c14d568574aaa56ddd3e56f87897cbe4189",
        "808751af5f7936f20d1c79508d98c079e42ec26802ee238a5a486018",
        "5cdde10ca4df3e7e6e0e428f683e1c6ca0bfb917555ad94727a3f344",
        "96c9f54bbb7c63ad36f09fc4de42a3e61c4a33491360e766d2635d3e",
        "5e83cd0d8dfea629b12ab8c6e1c2df0089729c23ffb21d109dccc917",
        "1a9c2111c4a9d73e5cbc5c8ed256af02207d2aabafccc8e70cddbfb5",
        "5befbb1a3609e66f02de7118c99ad3f230eef798716d810e15cfb3c0",
        "3b3bec249c71f889da3510d2c10187be2627e52f725eeffa1226a329",
        "f00511a8953626f69c9cfb4ae8329779f041f5e63122c6f93670d314",
        "0148ae1b740a92ca8ad7fcb515f0ad9301ee0ea241b282ea8e2a50b6",
        "9f3627745d86616e32363b8eac19c611a64369716ce1e6148639598c",
        "b82da6008e317277ef651796e9ff6307f46eb73dcd1063936a3e0900",
        "81d1cbb812a304aab0b444da82f0f54ffb4e54c6c3ccdb9ec29749f0",
        "77f30578ee53b574449317ee1601eb0e7772b8a0087fc140d1f7580c",
        "cba225bd2ded28f5b9b3faee8ecaed82ba08d2bb5aee2c3740e7ff8a",
        "4f4ae71e59c3fabb4fcbae6d2c226d2eb1e50a5f4a949013b795f659",
        "8129715af24b16464c88e301223f05a522495636b31e5ac8061e9231",
        "3ac400d2f10856de38052406c3dfeef146442082e91143c019549063",
        "644de73b6c13ee5dd926da47f7d473b28013f4cff8ef05781198b62f",
        "6b1335cddc139aeb30beab526885a57248692d34bfff2f8ddb6f00a7",
        "508079d8b391b21b5574db4f0bfbbf95d65784e5c069dae6c251f1c7",
        "067d0ee4ce901292070068f1d3c1ba2d4168e75e1a541421d1bfe5b0",
        "4bc4559dac077ea97f65672ecf5a78fb648b199106d1804bba5d1504",
        "2079952e2b656990e9398663979504f0e1860a158fd7900cc616a512",
        "9d99e821cdf3ac359990879e53b806efe9b7880af6f6302d5d3eb5a3",
        "1b093a48b5ef68bb5aab52c2a7c65d47b9f2ee98b02f513072d18fa5",
        "57e812207f60d0aafcea885895a61e8ac3607238bafb2d8f32b96c6c",
        "4688e6f2d3665d856f31518f6eef480fbad82d7e5a2ba00acbe10507",
        "fb80f64aec24828ac6d16961a081ad02209c5fe0e3efed48661563b5",
        "97509c5c1abf2b14f1b43dc961ec3232836562b08495193466fe61c6",
        "964deee5e40ef150c989e4166bc27741bd5c5b472115d1d2b9574804",
        "a0ec93c2fab048b46c4aa2a7c9c87f7d89be2be18c91ff4519017e8b",
        "08bec8a6db547ce973b8b7855b9234c6fd57a1a8cd3f917b9dafd5a7",
        "2363dcef05a74926b05bdd528389cb82803eb2b3eb38a761721f05fa",
        "6a48476a0b96b93ada20d682121f62f7618e345a15bcee8e9e009561",
        "18e87d536975afae2a46406e6d5e6e3708ac6eec5d3f62ef027e274b",
        "d955163f6bcd980b88173cb8044844888cddb3ed04f8ea06823e24f1",
        "2c36063a6841b37ab279c72587a9b2ecb35462c9fb1db2487b2369d4",
        "42b8c622711566ed8bf1f5e0c0f195578287445ea228ed54574fa7cb",
        "06413e7df86bc5802a81d014118cb339c5debf2ecdd4cd268fe094a5",
        "78fba635cd6dc57f91204f297fe3698bf7b367246161ddff198fc59e",
        "f3e59764a9261a25d1f9d8579428b4d4dc211f3a5960eca404709ed6",
        "cacf06cbc0937aaf21f26994f3676378d5755a1f5e969474d6cd996f",
        "3ed53777ce44557bd74ddf646d9edd87813b7b55c570afab0239b3f9",
        "8aae6a359627d027881b1193087795a9dff3c6f7965f3d0d7c62f406",
        "f04a158fab0209666427f4155228ccd1e8751832e915f77dbe4057b5",
        "98bbd6b7bf94e396cf89784b1ec76fb6e1f59566497c39487038305f",
        "7627b95c5acd864f9b40540f7bf0bc58bb0df4cae569018db354e814",
        "bd905d0c8f031b7a101d30653c96348800a41d25c6a45e7b52dea231",
        "f4475c2190a9f19e9c4fb81360df6cfd14d19f20e1b90667417037f5",
        "80e00af563942c1d7d8ba1cf89f9e76adbb83eb754611626c68e5719",
        "bed91828f69b8542c9d806a3d9489bd6b9620ebf5839f23fdcd17980",
        "7f6caa25a301a111de022dd4f7752b13fbdee3ec4f149d0e8be4435c",
        "51aa4de10a1cf54c04874d5b63e07454ca82d1ae951d10cefcc7d2fa",
        "fbb95341a79d03298f64fd990118d3a34ecc3b8124d34c49f43a4b9a",
        "6df1f556a68500af8493d9dae563e09b7fac3eb3502cf02239090e56",
        "e949be74d8ad133992a09a253d2eb78dd15c94525044643c6e9f6a2a",
        "0920f987b48f4695cd1b359815c3df17232af114838684fb18e33b1b",
        "e077f2bd475b0b36c99df5723d907eb4ea88aab08cd9413c19fd3bf2",
        "49d941737259f090b632dab5627666dc62cb1f3cbca35139a6475639",
        "0e5e78343720c5fa1b07578bb28b2e06112cc827961ae9fcbe6efb78",
        "70e280974040a1b981db605599405357fdd55a3cb633a25822425594",
        "4917932cbc82c60f903af142922993d67cb5a1b3845b86f0689e4392",
        "787cd4586fcb1c1fe2b87b9401e96057bf59d826b8e88fe6f555e9af",
        "867273e7b0314c092de14254f7a36fd1e18ae31cd29d01052c81b6a9",
        "368ffbc58630b68065cebab9ed34cb2e2f6a9f92dca58990fa74ca63",
        "890fd5f91dc9c2be7d1e909a67ece4df8e5a07126c631f021d39cf10",
        "70f9ac200944a8388f750a78b95c4465860881457218805f2a67f995",
        "7434b7bf8ca9a8c3bcefc5349ab6b58cda33eb4e54787576501f148d",
        "1363ffcad7ec4d65d6c7e2f264336976e7c4ea9c250cac6a14fd9ec4",
        "9e889c928ad2859c754a65f88d8587d66162c6097325e9802c0a1f7d",
        "751248d67a8a52af24602517ab8a9d0cf65f889041f0dac8844e9e59",
        "320637b0f3037a9190ef5f11afab2c526bb36b63d666caa7ed931c71",
        "e31056a44b0757a3187d360a96e8d3cbc23ed6c24868dce5329d610b",
        "21f49d749bbc5d9a743f2cc647e17cba15521a4a0e8a46bff6700264",
        "ed2774283bdd29c5262512d25646f351c8e6b8c4a722842fb162608c",
        "a774cb9dc56be71ad8a4b134249d5d6a35cc19a3ce9631102f73b2b2",
        "4c4acd94eca73f775eddb1336fafdb01bb40b01428d0eb619f2285c4",
        "6b3a10978f82de610ddb783f4750f426a14b4805b44c5d33aa90b58a",
        "d5d93458afdf8117b9720793981318c42c371fdb37e155db09d04113",
        "b3d2dc6660975f156c8ab409ed69e85661819d09ec263cd12702f541",
        "b4fb6935f0feea3c2aa1f518206d7f11263d1bde453b2714d7c13754",
        "5d2509a3bae211028f0fa038a924d8b028dfa19a4d57c1e942c76c9e",
        "c5cc516974db491e8d860cf1f1b7f42c4168bf9346420596053b6c9a",
        "b04d336b3ae718cb9374b455dbd55e89e3cfb12e05cff08f59bbec8e",
        "a89b063f7f1665bfdc95259c2b717d97e8b9626d659ab6619b55fec6",
        "d91f57a086889a4db6d41405595b99c54b00cd25cb658a6ac6dcb09f",
        "2dc472f2a127f6006fe8ab1ff257d5fbb426b8b445f0584c0226c5c6",
        "c1d7712cf08ae778946226d6fcf7aaa696f65043a3fbc8f3af7eefc1",
        "1b3507c41c13676af4a729ff4f63d9800d0518737cf9d6fbe6de75c3",
        "3aa2d70df3ddda2afad72e94a1eb8e801c179d4d0ac99b888da822c1",
        "81178ab27b7f9dd323699986687b4c1df9a4d8c90b3822fff9b2e859",
        "b699da6870355106d3fc29ab95b4e26463d680b35e6cdcdca60a24b5",
        "2d7d8149b5a8478d4666d90c08c1e63a565f672c286a8b78d622af7c",
        "3c622accccb2981f84e3991764c9396fd213011b8fbee6e7c0b0a7c3",
        "bd72fe2aada273af8b0753aa24782c32e7e0034f45b7673d1c3f428e",
        "eac7559bdf398358812ea17efb96ea6c1a3bd364607d15aa3fda5dee",
        "882e94cd813000756e895bfc3372075f2f9a7d228137db086f749f3c",
        "8cd86f0cab5cdd871dbb0d8f8f09928cc16588c79b40e7e826e54ac3",
        "30257ad976ee6873009a5d9daf6e53b78e85529ebe2d7c49100bc9c9",
        "7c80865a659c060162b60c44fb4ec62fa8ad6d4ad512a64fae996a44",
        "7365dff85010382fd472139926222482ca12d49acf1ef5633e6fc4db",
        "a79660bc0860b85e16d7597bab3d6392012dc504a94e02bf9e4bac83",
        "7309afaf1f2fd5210f73cad71084ae904fd4972c5ee7489569f3f986",
        "d9edc63d985cc5bcd77c1a1b434d7489c43964aee7dadee460334ce2",
        "bfdf902af71c1bc2a5a5a2d9e269700d424495d50ec4b3481c600e19",
        "b42efbab6020f162d99a1a1a6c128192dded3a0f06a4f58561fed55b",
        "0b3274c442815e3570d6fc715270a9ec86bc2774a2db05592b700271",
        "d2c64ed2a78e06961cb6c91effa32508d73897536240f98f9eaad8be",
        "a8a6ef18c9929a2a3868f557f34f0d1c4637e26e95c939030609afb8",
        "f2acf3a0a0fc9d4ed67b75853467be4d8a6bf249ffafc4d138aa13c3",
        "89242250fbcf58bd930041a2fa1f11bfa8ca291356119e8a67b96f32",
        "4401d1927c45562c9693265347afbb92d1fa3c8636a6af9dc93ee8f8",
        "d053e10768681d9d5072df6dd12fb776de78d1c0eb1d0fec23faa9bf",
        "de4d83faa84e2e2032688e87a2cd082534429502225a08f919b2e92a",
        "d4fb42ef021912706bb2dd3937a8de0f82bbfa4524cf962dec2e122d",
        "20c98896b9ab722bd3ce785ecdcbd11b7b86f5760ee5702ffbc1f84c",
        "1b31dbe14b33ef91d0c319887561dd2bb4148d334a54e1384e54d724",
        "8cf5def234549bfb8ea921e47930a0b22e11aea50fdb4de0adffafda",
        "29b9c2fd80c54c5f374b0928adb388bdbc61518c614c789c679e6e2e",
        "3a080368d4187b45609361548286d215edf7fc16aa477c819d0a8433",
        "61d3ca6b6a72b80e18364aa336a5c985ff9497b42d839e578fc45c7d",
        "2ff6e275e9ded84d04d0d54d4d91799ecf396bf102050afb94875231",
        "b6ee191a32e92d7d26581bc2bd7a8c8842005a40d7e70208b3d475a7",
        "922ffc94b8c3404c824c9e8308f8264f4ad3ccece15cb5be6f0fb0c8",
        "a547a1f050d4c695e5987396ab1592baa272e837db7e60e8d809750f",
        "5860c4ca2aab22f16d20ec03f65fb91d30c52949ce9a103a4a493eb1",
        "fca6c685486146c8f500de331b1e9f5748ec60052763bbcb2034e558",
        "926168bc4009cb417523daf5e994b7744faffc9e0f38a9a4d39ad590",
        "37a64bd2acc1039b3b7784d089cf780df774f73d577e96948ccb095c",
        "3fd0071b8bb80993785526428e54c777dd93b287010c7a2ffac0658e",
        "d6e48323aae4505cc59c122a7ae924f4616e651c964ce9cda94dfcd5"
    };

    const std::string m_7000 =
        "de2a8d03466a6e3d5ede51f91b2f264163ebbff72dd7d9e75a4af8a5";
};

TEST_F(Sha224Tests, Simple) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Sha224Tests, ResetWorks) {
    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_NO_THROW(m_hfun.reset());
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Sha224Tests, BasicInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox jumps over the lazy dog", 43));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Sha224Tests, ChoppedInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox ", 20));
    EXPECT_NO_THROW(m_hfun.update("jumps o", 7));
    EXPECT_NO_THROW(m_hfun.update("ver the la", 10));
    EXPECT_NO_THROW(m_hfun.update("zy dog", 6));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Sha224Tests, Extensive) {
    int i, j;
    for (i = 0; i < m_cmp.size(); i++) {
        EXPECT_NO_THROW(m_hfun.reset());
        for (j = 0; j < i; j++)
            EXPECT_NO_THROW(m_hfun.update("A", 1));
        EXPECT_NO_THROW(m_hfun.finalize());
        EXPECT_EQ(m_hfun.hexdigest(), m_cmp.at(i));
    }
}

TEST_F(Sha224Tests, SevenThousandAs) {
    int i;
    for (i = 0; i < 1000; i++)
        EXPECT_NO_THROW(m_hfun.update("AAAAAAA", 7));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_7000);
}

TEST_F(Sha224Tests, UpdateAfterFinal) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_THROW(m_hfun.update("Hello", 5), std::invalid_argument);
}

TEST_F(Sha224Tests, DigestBeforeFinal) {
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
    EXPECT_NO_THROW(m_hfun.reset());

    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
}
