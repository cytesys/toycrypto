#include <gtest/gtest.h>

#include <toycrypto/hash/blake.h>

class Blake256Tests : public ::testing::Test {
protected:
    void SetUp() override {
        m_hfun.reset();
    }

    BLAKE256 m_hfun{};

    const std::string m_empty_digest =
        "716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a";

    const std::string m_fox_digest =
        "7576698ee9cad30173080678e5965916adbb11cb5245d386bf1ffda1cb26c9d7";

    const std::array<std::string, 133> m_cmp = {
        "716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a",
        "d8cd6be396a8f029bc46e48367d3d84150776c10b7a6affedb19e8d0d175a708",
        "ee7d64bc82acabe1da5fdabdf992cd9b27b5a5f26ee513858908bb0331e79ce2",
        "c06ed62861ab23d1aa1c398a0b670e89dc85e2fc894676abdba4353cb48221a4",
        "0dd4375066df0e5a2c95fbe58ec0ca260d7c84a1f5054ac8f1636611dcaefd52",
        "68bcd4cafcf15b386b12233089918448cb042b370536ad6ccd8176565b9671fc",
        "105ae1b6c4f4776dd84f78a676518ef30ff3799b645bcb76be883aeb7da4c5f6",
        "92502d54fee06a0c630ad9c84232cb36f0410f15b50d0da9497ce55d0bb65e07",
        "5e9e135aa13fffbafedb5992bc6128e83b919ed478a64b1e6f5c30c797090dd4",
        "f921faac0813d63054ab391ee119dd555a3d21bcfaf65f5a51f04a2b12091343",
        "c7aa933f5e08026a803489d10baff90faf485f35817348ea9ba72760cd31fff5",
        "d8c319fd2151d5867f1aaddfeba249d5ffee3e19f50256a71982a33aa2bede07",
        "02f4f50feafd426a808059010bcef1be4b25c251a52bdb09956df78da040cdf7",
        "1f567d063d3b12f827fd70dbd1c0fdc133764f81b7dd3997c6daa8512dc4712d",
        "d903941c5a9484374e8bd776ad8a73ed4e556809a7a5faf842c5ec6fe7242552",
        "76cccae3725d8d70e552920a5bbb76d4cd6e0b048faef96ff28d33500e127416",
        "99becab70375e5ae6d6a517723d89c77ae45e216c068ef226c1677c9dca505f5",
        "9aaef551721ecace2e0a8a58f814919f8db64b06ed5b9d3edf9bc7dc7b266954",
        "be855e3a1f352a8c6715093450bded35ed02dd41dce59e20a8fcb6c8c234e1e2",
        "ac0e3ed1c6fdae3683cde13649e0a1fa10dafad24bb2478c62506ed39815e75d",
        "6e515f3dde840ed799587b005db2fa9c82758b12dd307b5116392238d917faa2",
        "fefb67b2e6e0fbfdddc930a80079faabfd8eceb60309bd40b4eee95695c1f4ed",
        "4e259ac90f2274fc0caf6e8d814c89f2d384ded190f9c93377a619e64a43a9bd",
        "dc5bc3dd0c7c736aea48bd1a4ee2148e96abc1309595c9406dd31f2ac4350965",
        "7da9f5357757eae3b20ff3f7e2b50ded79952b0681cc3c9a3ddeeeb005d5f1fb",
        "5cc9aa5d43961b98e4a6b0735777117c6d4446a15bcbb5dd034c989b03d9e25f",
        "d82099c65c35c1bc82fab210b293ab786552868e753e82903a5d5e1faa4700c4",
        "40f7e2f5024453ce0581f33ac6e183401ff304069b84e8ca09b6573045afac14",
        "41143f3a195bd4ef5e416b78c95fc2391fd6ae77422d37ca3fa55ebe5ee9892f",
        "711b94e980d51da6da83ef578eb76a3005fc2fc2bad79c0a566cc659a2d9d10c",
        "7e25a56e3ffd039e41cd08b441f8899eae7c0954da570a20ae3056bfc42b0dac",
        "dd2ac734502b391ead7404aa10c0e16efa6fd6742ae9fb5e5461066ef6049636",
        "65f26f42273815d61cc3fadde823c211d14fae958a4ec2a12a1875f040b361af",
        "a6ec21eec011376609e5444e0475c5be6bd2b764d296d81b88afcf8d8ae6f5cb",
        "ce3434578e7ad19289921bd1d65938fb4539cebd51baddd5281e87f503c58289",
        "881d958658f8f8d5cd3fe89227716169c57c016dae877fbd3d78f3853b76f846",
        "4345c982f327a7a5a2c3ba1f42748382fd4e8ed07ab288941ad53b16e30dd987",
        "86b83575ffa006a489f743d6fff8105b18a177a5e7964f98360c9c2c979885c5",
        "32b9dfb5da7062ea52ff81dfa9a486cd581f17a422ec9a51f1ddc3b6a66a7e24",
        "0fc3a617d397e0f852c7ad451950d67e64c78c66ab143a94bcc2a4832f8b8f68",
        "38de23514bf6b7d78596e1d11581720a9232b9f7579e20a6e7876d53b360b4ce",
        "3aaff4bb413859925eb08998ed506bde6d1e5d88eb4b8be9141ce0a6dbbf4dc2",
        "0132d03deeae5522ac38405f036bc383843182e857d963db62fbc4d8b9b74ab3",
        "8484f927c26ab13dca67aa1391552e40e9bb5b4ab864867c8ffbe85b1740e24d",
        "60361fb842a21c3127c0c3e77eeb6d0adb1cf8272c903539d0bff4ec182f2772",
        "04aa0f1907d7ee94f31cabba0c2e4952df5b5c91aa37807245e0e97d46dcaf4b",
        "5d9b93c5401c99be57d8ee67b224b13644fcaaff68753dd5b112e5e9aa038284",
        "6cebd2284027fb522406d873b6ccdc10bfc7c14011014ea508f9f72359b54381",
        "369eb5283197f9877472d4a46b23e80e0e6bb35252822acdee49048a8314e33e",
        "98a6a80a46d5a9f64a52af47bf16e1da1645a2d9c8a99675d63d69fd20bea30b",
        "dfa7179b5f41ace1b6dc53f74d14a51382bf24f2a19121bc93eb5775b7740f74",
        "e4c02c94aa02be7a193d0a90da60c6f12ee18ea22a0ca6041b03cb11eb81b206",
        "df41825e56d2a6a164f9869831975fd9e1940f567cab6210a396ad20560f50fa",
        "566d4f84d943eca3702a09545f77eeccbed9c4bd5b3171ed3841cbe8b0fb3439",
        "587b4a9f58be185c2b05eeab7fbda066459c02b8f6d7c58448b60e6430e48847",
        "28a1e0b1dbb8fe462895c7a0c8d767e80f179197305faa6bf275caa27be12687",
        "42432cb46422165b1b4cde6d932c32075d88d64695200700d517c4a27aeaf7de",
        "04cc5a1d6a36aff07fb563b003d7c79d52860ead7a2acbb1c312379a0f44cf91",
        "3ca78026708faf3585e65f193e3301110ba500a0879d32a5ca4dd3a2b9137672",
        "08e3a0ce21dc3fe5234656c970fd026b7584d9c1332395f2dd9d32c542433dd3",
        "766d49f8a93de99bb6559cfa7a98de2c3a14ec89cf3b2a860316cb58cea401c1",
        "87d3117680e0d815ca985c7bcf7550b287f4c0d887a4ffbc25132b657cd81a6b",
        "abb82234047e5d4eb3593f59787dda70bbdeb91ce5423291ba105b69d434311c",
        "885225d8159f6a895bab7389ad3cb2a4b1c340ce6feebf674064ac6c7dd14c39",
        "c488c75e40ad5cecbc080b2ca50bae9545e051b8f4ef93a8e685ab1d25db7696",
        "926139c0e3715a29eda0ffbb2c503da48c3f4bb32afce3c2d2e695de77280069",
        "15426844dacbb399e7c9fb1d5e991f773b9d971f905a4400db3bd03ebd02c529",
        "b9e0bcbad7acd419e74a11ff4633bf9e72cd3c71ec2838734c1001b0f7d54e5d",
        "71de4581f664db195fb799022d1bde5d3f59d518c360b166cc106da25e770152",
        "6663d063c51d25e3c30a223633c8de697d4055dbc0ead022bba475f71212e944",
        "b0623b6994e666104f8367ad7e33c053a488c8a19172e654692d0fb415e9c7cd",
        "1c6e20cf5bdbc24b08cfd3a508cb8bed1797caee53837febe63708db9cdf6607",
        "67c335a0967d80ba765c47ff9a98220973ed906e77ea9f1087967a141a523ada",
        "3914e8a4a3af456f918019ca5689cd23c134e8e2b2c3b08280e33a059c64a36d",
        "f04ed0a9c1b4625cbaae619ed6329fa4d66fc3db7a3d6ba5a4d367c35f01f18b",
        "4809ca9097b049ea15549c3427ea3fc74e2aa34e06f24b9944dd887e6e3d3736",
        "c0e1fb26808defeb3f815adcf5c5cdec80717f65acd321d2731e316972b6afea",
        "6522a5f120f375bebde3b5c298c188a4fc1b2eccddc5fc0fb11468cddaaa6946",
        "1d01508d9f224d179514d5a306f3588c54d63cb9113a86d8d24f4aa685e6372d",
        "ddc376665df88b13c6471044692a5d6017cd9b06d17e963bfc7752335a3e652e",
        "bab7a84748ef73902b0cb92b54a05519182bd39ccfeb08cd1afe94bacb3d771b",
        "7d8ed63a91535a85eb1a34357aff02dcdc3c9430c222fa8dc46444e2b36b5612",
        "5e04b6f87d28685a2dec8ca1de990a3cf878a56fa190f145310c5efe7cfc8449",
        "e68cb77a5be753dbcb0e992df46d0c01e03bba548e51698994ce697a32fcb364",
        "2b2382b1ad4645fafbafe4583170bfac17767fe073960447fc858cf0f0864d08",
        "94d07c86d700d3821d04f7d0752957a66394dc07d5eb6f71607f993edf7fcb71",
        "fb67ca52af7cb4d08c0b10156dd9991092579ac6e5091658c304db232fa7aa7b",
        "3f6b8325351c84b8ab8a5f3d374471903bca16ceef5b218cf1b43145d5867ae6",
        "4bb880233ee4045d6c7f2b3d77c939adce9a19e7be0a0411c44ebd7963c5f6d9",
        "aa08331dd19cc4ecbf59f220a070f8002e56af57a6f0469890c9e6e607bde64d",
        "4eb1d221181a15a052973b86e16306fa2bcc8b3b49ea6d4cdbba709e8090c37a",
        "f48854685465071304f9830bb837ff4b9a433f0fa0549e393bca0ba0fccfae15",
        "f01fb859ce60fca215dde4ed15924ec0a9b25ec6243fb4a743017cf3c30ef4cb",
        "49b5f2e3f040c9856a68086b19fefaf881bd8d409a153c0bb3011143ccef719d",
        "13eef4e3fc66cb5e4631d737f4d5cfac06a0e568a6d0f425a7c9006456117652",
        "d67ad29754cdc12e25a8818d29e60fe9d3ab1771bc2d3fed2ea772b1efe3094f",
        "09f696601d901db5e93427e40b1987a04c00e966e782f73db7923b6b07553193",
        "fe6a994491438e003127c5779f8d4e6eb3a4670f95ff53841aee761720bd9804",
        "8bea60214a60b0d8424501637d68294b7ccd2e566594eff81852fb1fa55acc6d",
        "9db7235150c7516510f7ecb945a0834d42eb1fd93c8e74112f6682b807aad5c8",
        "7cdf04ba7a28f65d1b12731c783c0d2209dfe5e16ca44618ebacb9cf77a57a95",
        "e231e4d7f403299269c4276d2d1d38019641dcf9b8b899fe00549aef0effe31d",
        "fe497cb90985417e00c4274cc40b3fccd8b0a689543f71667159fe8758774c28",
        "1a7c57b8f0921c0ad34e69bd93787ccc105629550f7e59c7c6d4dc1469e287dd",
        "9ace1063485fb71ab1600a974ff89fcc1554ee6f77bb3d0251a7622428fdb526",
        "3ad3dbc617eedf4d086fb7b89f52ee9f2bee4559f0602a6117e1b13c69fd1346",
        "a2706c5f431eba3b467094749d444249b919459015988404f360255f7f6c3019",
        "6e0c7cb45940bc049b3fb0aeba11db4398b8a77c3e242635b99a372192470d4d",
        "08ed44e66928d93b2033d1bd8efadb620655829ecb8520c56d552e8357387d07",
        "2714fe03fcceb7cf558e643818ded8a44b72a70705e7949eff76bfa24327c861",
        "79672c4e002bd781326ec8db17ff991256b9ddd32e6ffadf2330ee69f401851e",
        "ccba2d0b58a635d289da75f368b5981810d942d83f76006fc455627c853610ff",
        "5e882f2878aaa2c22357de28e29470b73a7c724384cc718c59c8c83d4b822827",
        "7a9dbe23cd1f5191eed2c120f417d9c2fdb4c540956709ef305ecdd6117f6a0f",
        "b2d32c1e95bd1085e401ee061a92357dc61f541f3c004aee1f11973380119564",
        "049fe65fb82755089c99f707e41b95cc8034f96753cfa52651e7f06ad01346f2",
        "996c0dc8d6444a669b838f47b672b521049b9c79b91482068c25a565c18491ce",
        "c3788d2ac3b9b45d9df755e95cd720f0f1e6b963df43e8c7ba7a1f652ed06beb",
        "6e24c2ab5c649cd357f8145a80132126cb68f73b4fdee5999bc2aef4d4ba59a9",
        "78b918a810fb13b4a372f2280c16a459f0f1f9bc7252719769ea457aee7478f0",
        "1fd85ab0841d796ef24d84f10a3d32ce87c908c73b27660d37883f7142fa2715",
        "af3abed0f2a03ff93d4b05cd32b4b5924b2577537752e78ac2940a0c2920f8e4",
        "bc04125bc401b853fd8f428a11c32a02a29244638a4aaefff28c271921ee67f0",
        "0ac9db4102b18fb3946371a2f9e25db2d3b95c1c642a2b54b1daf5eaa71ae0de",
        "0fc776a0f6b2190d89ad2f856e0b3e564b7babfd5ae680a259962fa897e72ec9",
        "b89da5f7cf84303719f749a5854eebc2a540795db0aff5c158f2c2ac8faaeff5",
        "862812512f4facee6abd285f132699b7dd81f29d5430486d182d38a978998998",
        "5c39cb125872d66a46ce471aaf93be3346ee0ef3a11e4592d801e90557cfe172",
        "eea0543149487e5c887b265a9970965306535b2e4640ab8b9e44c5224626df72",
        "b87d8191cc14d9548ca640a20fc71336fc5424145fd0da29ad355addbc390f9e",
        "0235910ee7361e982a5c6e882a1ae5114802df157638d253232cd481776a0bea",
        "72f64b20b192de0db4f5e6d21323f64c0917f12b685df30e2d65f9962a84e4ee",
        "b2ca865746fb810e5252fe415ccbf0b550b4d17580942495eaf7b1f296f7057b"
    };

    const std::string m_7000 =
        "0126920df69782143e39386ca64cd3286ba6d335b638d87122734102b590e9fe";
};

TEST_F(Blake256Tests, Simple) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Blake256Tests, ResetWorks) {
    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_NO_THROW(m_hfun.reset());
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Blake256Tests, BasicInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox jumps over the lazy dog", 43));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Blake256Tests, ChoppedInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox ", 20));
    EXPECT_NO_THROW(m_hfun.update("jumps o", 7));
    EXPECT_NO_THROW(m_hfun.update("ver the la", 10));
    EXPECT_NO_THROW(m_hfun.update("zy dog", 6));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Blake256Tests, Extensive) {
    int i, j;
    for (i = 0; i < m_cmp.size(); i++) {
        EXPECT_NO_THROW(m_hfun.reset());
        for (j = 0; j < i; j++)
            EXPECT_NO_THROW(m_hfun.update("A", 1));
        EXPECT_NO_THROW(m_hfun.finalize());
        EXPECT_EQ(m_hfun.hexdigest(), m_cmp.at(i));
    }
}

TEST_F(Blake256Tests, SevenThousandAs) {
    int i;
    for (i = 0; i < 1000; i++)
        EXPECT_NO_THROW(m_hfun.update("AAAAAAA", 7));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_7000);
}

TEST_F(Blake256Tests, UpdateAfterFinal) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_THROW(m_hfun.update("Hello", 5), std::invalid_argument);
}

TEST_F(Blake256Tests, DigestBeforeFinal) {
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
    EXPECT_NO_THROW(m_hfun.reset());

    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
}
