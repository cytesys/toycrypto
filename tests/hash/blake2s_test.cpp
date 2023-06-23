#include <gtest/gtest.h>

#include <toycrypto/hash/blake2.h>

class Blake2sTests : public ::testing::Test {
protected:
    void SetUp() override {
        m_hfun.reset();
    }

    BLAKE2s m_hfun{256};

    const std::string m_empty_digest =
        "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9";

    const std::string m_fox_digest =
        "606beeec743ccbeff6cbcdf5d5302aa855c256c29b88c8ed331ea1a6bf3c8812";

    const std::array<std::string, 134> m_cmp = {
        "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
        "98e14bd264b8837ddf8fd12d6f5641d59c369720b02c105feaf99f1b6a7b9618",
        "a99ea583af303d4ed21067cead52d67b11636fa6ec241f9f6cf5beda55844b8e",
        "8d4fe9f5368ff397ce7444640f522f090597591c21392262138da6750bf1dff6",
        "ad0b5f0ea7abe50530487c4d1f0de59699955eca58fa60372863927620bba191",
        "ac7051c3915e46c4c5924cfadf0942889bda7b2cd2b628f6c5e56989cc8470a1",
        "49854055f9d89a2a6dd1a98a6514135c7eb64fa6dad96c5cf9fd230ad9070c03",
        "b913ba7aff43317cdd69664aea6b985e5f1581c1f6dd094a55b474d8304f906b",
        "b4a5fa29d464ecaa8bc4374d3c693bf2bdc4caf23e9bd95a41a5618e07fa03c2",
        "efa6be8c39474de57693fb05c37b8d042aeb5fcff0de7a400248d51ec04102ef",
        "7718838cdc1c1daed92a4787d70b3595516d152c8fe20cac8b7f8c3fb5ecaf4b",
        "c8a34b6ff4a2b9568e5075ecce59d4986ef8fea9278d9aa02873b67300bf0fbd",
        "4fff9f161260216c4b44a83b1861d66618ef2b610388462b5af0c2d692838ef4",
        "276c35942fb1222007746bc89ef6f017f179677e870e25eb2df763f21a197e93",
        "914d90b6365cd17d12d91ad808d756faeed6e23fe1543982335bbb5e1d478630",
        "4f89c5d92929ae95471dd1ea857bf896176c946ccaf639aa8052f12136604a44",
        "5ff2cc0c8c601022b241c096216795e06bc634ef252e006d71f8940a55613229",
        "e59f18c2d1e74f60d6bb10d28933b4512b7d506c8a0942516651db530f1761e7",
        "c56fb65074c5c4e8ee116338bc4fe60c1795590d5e2ebb4235fff6991908e14e",
        "8498aec99e0344f7352f8552dc7fb05fe1cf8c8bac667ba9a26afcf101cd47bf",
        "141cea270b3e80fe396303cfea074eaa09067a3eba3d49750c057e74e101a16c",
        "c4d372991c3662d2d575aae04949f608b3804eafa872bde75e0bdc49107abe94",
        "e758d4f4bc135babf4cb817d13099ce3028ea88eadcc60c5abf86946bc9eb36c",
        "6f69b58273c88399afeb3c07696b6ec305ec6093bc8c1cc041e101b185272738",
        "0cacd9e7f6fe1e205795b9b9c9ff54048a96a09c0b749f402e73867c0c726c16",
        "3e4fa972facd8978a058e64a800b965a4f29a987c866082c0eb23d021d2a8c5c",
        "214f53ad5d1725c1d7f517869121d7215e07ccc4401f07ee69a4574ceed382be",
        "c95318ebbbf07ef3f3f484b2776e463ee89893ec7bb3845000232c1497bfb970",
        "5b58cd59e71d355bdab210c938ff5fcf86f6e89bce68d79bdb0a03a35f03b788",
        "76d0ad86b8bdbbf6d3064cbd9846106d012d8eb3a90059a7b431981ed5a61041",
        "f43606963e5390c621a47e7497ba0856ab5a328f1958fc63e83e9cb79eeafafe",
        "52d076436c1cd79186d745fe70a3ad2bdcdda480ff817e6438f2b87c8673f4f5",
        "58d07b9bbd996e11c020faa4b62a23f6eeeff444d3cba5a69d0f95189fa6ced6",
        "f854ece6f634fe3cd906b2d2705f9324e549bfa52c0636e6caa0ab78193e7523",
        "2159435f47c18551a9aee159760b39954154451d6cc426a8880247c362e86636",
        "9d61bdc7aa36b0b0c316c350ba8ce028660105a806c965a604e3b695af2a90b8",
        "fa31600a5d4fdea10c036943051b787eef30f696095a30f2809f171f3c27e5f7",
        "a7953c71f6681b7fa68e8fa6312bf5768bb46033e758766d0f5c0cf3d2380942",
        "208161a6f9f7504f9d5bb9f2716806eae10932f4edb860f448796f667362890e",
        "c9faf51d5dbafa50feaa966071fff80fc31cfd1d3cc1ebe0b8ab18d8fa223706",
        "a5940e37c95d66cf116f262c4c39b7da31e4c4cc66af979250a2b79540a2ca2e",
        "2ba9d685549e52fddbf18351cd0c15969173d11e6aafc39089d47837478baae3",
        "00012a978d4d24af0474d79e290e2f4d0dd7ea4fe780eeac25725e8a59191eea",
        "b5de0375683b51f15b0bbf6bfbdacfa52f22f57c9ea9f2595c786af265850ecc",
        "042100d0e90f66fc7129a97f0e8921f80324a2f3748e9ddf3a8fa2f9fea8b59b",
        "58f8fbe88fd265fbe3239ef4e1591a36ed5a3f100b487f7cd2dfc3e38d6e6abb",
        "a13b6e2080d6ff6147dc263a40b09198e6124b90ee52be2bce0fc69fa4169992",
        "c7b24594d5c9375337f726df515e26ca751198ac59aaef8a636a3ea0bfe3e58d",
        "f2002bc2615bad6b037e020c93d27cd3391b523827f05cec10f9c092c5c47e2a",
        "3ad1882a3da98a7ae0e5c4589930fcafbf335d0d5eebd357d4a68bbb48c20e20",
        "f87ee4ad1499b35cdf02141256ccb4caab90a2d6deb621c87a11711ebd90a53f",
        "474836cc2527be8f0373ca4304283ee07feda936f161efc48538810435bd85b9",
        "2cfaf7f14886a4f5d0e87b5276d0dee47deca80e033e3e0867abbb15251db129",
        "b496f0f3b8e57bc6bd4af533708dbc07e1479532c188a066d19885ca11ff6879",
        "37384df58412a8a97b97d7fbf91c9e36fc8b45496b65fa3967befaff65cf253d",
        "612e6af78a48cce0ba83d42c1263f9b91c73d0691186a10d67fbc01275ae1294",
        "1e58a5cb278908b848db3e6c2481b84a9cb701f2f3bc820ecf424d458b000807",
        "aa877b8a27aaa5099be48fa67662b3f5b5061158572fefc4b156f59480346565",
        "b9c301e38bc22076b2338103667fb3ec967163c6e0390fd1a8786b03f7ef9a05",
        "529240fead4efcc0c81bb3a21c50bab9f3dc338e47d28d9e8a5fe3c9bca5b28b",
        "356afaa7c790a274249e7931c86cf14ef5465218b2a50f5f0050c5055cbaa177",
        "f90f672898e953c16f54824b898321ed748e6b8f1d9ed3f01b8b189838ec472b",
        "671d3c590475cfb9c3974c605246aa0e90d9aa017c5e9b9b20ae69031bf6d107",
        "eb2734c5ef4a1f1ff7bd2e7bc43ded50f138ca61ef8e11621aec8ac0ef307217",
        "f85b88e0ac55872416d202c5f4881e7dbc9c7270542ef75074ff9b0a610b5a0e",
        "65bba861969fcb5f1d8ec69e1dbd3e891f546b02203ce73b27958b9589a6789d",
        "0adf0d75b75a6f338a0a0cd273e6a081dd5c0ab13ae3aa46fe79070e10f83fb1",
        "f7a54794b8d201ed2e89a3fe4a1cde613a5431a7468217430ab8e94e5a452103",
        "823e2f79a9328420d583cfed98043ad92b297c79620fdbe3e2d6e9d8e897e461",
        "bd9c051073c2d621788a59e7585ee406dec42a8e1e0e52011e22654b89661d59",
        "336d18e2484c7089de50741178c143533942a9969819d2ed5a2fa89b1480a703",
        "3bdd2fde1b2baa397f92f5c4f26a73e31fc63e312448e257dcfa233a897f9e08",
        "c4b49a77ee46b6c166d56157131d1ec182153d0004428d6ac011edc942becd93",
        "d58b17f3692c3d419c61fb16531989faa0940427bd64136b9b44cfd32dda4a10",
        "6eed53a1030f8d037dd9aa370bc4700da98d56faa99a5c8e85ac5397f6ec2a67",
        "c9e71f2752c27b379f0aa90a328f0d67dfb77e2c6bb8ea4a8d0e8512aa143c80",
        "306a2a151ed78025e952403d7fd165957343b13616b0d423c1f372faa172b989",
        "4634ffb218bf141e0f48bd1faf9f0033525fc1458c4641234ecc0966a8830e83",
        "b0590c80b2753d553aa0502b9a01fbf3fffeadd162eb7fbb942bce6834df7731",
        "399eb1edddf3aff77569d2c818ed2f8d534bafa96a022549762b155812a1ab18",
        "26712b2ccb5548453618d417a1c9d8d1c6fe132e748d58d647e2c28ec1a16b75",
        "2cbb7bc641355bbab41c938941cb9003c26fc8c13eea972526a6a0987c2c674d",
        "b8f6b0e34cf0565aca12517f9dd062c3a3577591657b78b71944772e75806d5e",
        "e3302fa4084ef274105a9c7b2311e2b7bf16868d98854c449ac0bd7e1496fcff",
        "0357f77fb1bf27fd12aea8d76fa08dad56f0e9ae5a79ee3055ef69af502cf5d9",
        "c0c87673c4b5ffc386637967a13def30f4b48025f548019d03f296a1e47ca970",
        "2e18f57039347c24927aa761b2da90957cb52f7720c4aaffc9a63035e23aac94",
        "0c3d74524b25f5e3973e030556bd26580dcf1493e90f3a02df9a182873f22cf3",
        "4967b8e85452998ff005ff5631b4a011367e41fdaf0043195513e681db20321d",
        "de20ed8a5f886498c1014537c4886fedb0e1b1027240fa3ea958a745930798c5",
        "f21bd8117448c0cf02a06f106836d8ded9a11988c9fddf0d00e6b1c1c4fe27c3",
        "791e90fefc6f104b704e9ae50c105c3edd767e93f297d96238c41dd7d34d7bc8",
        "66524cda987ea07215fe2ad166325eb408c2f9de74f5ee8b3051a946ddcd6537",
        "4594f336267099245d46c61635090dc40bc5b9691b6b27a328fc0060f969a54e",
        "12781a375ac0d4f14ce4b01a8a3d7132b391b6d3d0065f8cdcebb6dfb227567e",
        "f4f03246d34d6c531f1eb296a305a7f29d01367007e4e0508a736564e4deac9d",
        "ade2938a6b8f740567ec10da7a57758c3cc044c101b8a8b14f8edd238423a076",
        "c49e476913bc203102619ccf5a2a8636c1d9405ec44320aaca98dbf94f82817e",
        "abb82e0b4fd69cc97ee99488d99f098b463a5df8336f219c895d9688e2260757",
        "7b0986c072aeafc2ce58861b54ee0a0630c25704cc1657f686a2578d909b9216",
        "ff079d11c39c7fe6231fb98fc130e00cbedd8c34afa0c1162890fa4d5f880299",
        "789d4115398d3d0e433e9d205befa8cc683966d274e8b03d4f353e3a9d8dc906",
        "060b3328ac173c2efba7f4d8cb3be7ed7a234d6c04fcc19e41a6543520e81bd1",
        "d8769dcff061bc77096e8307439a9b1665952eda2bf21d6e70a3511221b71ed2",
        "91373688d4131d5247778642e70084bc81e230af5cdf874e2e7f2ae62a1f710b",
        "6ae960c688554208827a1295ea050b07199e97b37475abd0131e0ffafd2d632e",
        "88923adf2bb60e0fa9a21e33c23261322757b6d1500d8db7217f99a182f5d107",
        "0b9532b985ca9abe2a43551e63433b499d8bebca501a626f735c15a9899132ca",
        "dfd841bcb09faf5ba2c91eb55464c4fd9e93467745a4f07d37904a1f82f4532e",
        "b0285d20c8981bb15946a9d9c8444870a88e03c40d1270ace67dc4ced88f29cc",
        "dcfda25931a1e0b2f075bccebe4940e900354252f6db9d27ec644e0bba64d13d",
        "33ec7cfb7f0f3f6d491a3d6f065f9b02a970271210b8470f83907cf66dc9494c",
        "c161c80dfc78a89c00d6209e44e39675c673a6422d45d5968fd2c710eb256609",
        "096e055836803c536d126cb4745b78a855a917dd874e45f8b214ae16de8a36dd",
        "26d0634b61af1ba7d261b22f40b703a26ff32ad1fb0d08db0ac4e79ceb7d48a9",
        "b3118801efccbefccdf67fc28038e2d21f7e6e98966f3371db14cfd70cf3f284",
        "a2da7a239371ca9a995326326981a8b7fd8ddc92b1bb88d65b672857b104659b",
        "2a029d303e5edd512eefd856cee6a52cc5fb88d716937563efb7a40cbebde115",
        "13cdcb5b3ef09c16866c8a056be01b2bb32977dde43309bb030c17d15ffce56f",
        "2fb4420ee5ca3ac970fde22064bdadf308c6f36c3d31ee41529892ce637b5296",
        "765156a4772daf45ba699cd4a40fb0a24bea2898efcf340d2345d08c7e23200c",
        "46596bdebd2e0421f5ce4d62f49fb615b0c3d5f5fc9874303ac5229cf87c7db8",
        "6e4c72443f2e8e75b3fa57abd396f95db27b29526947379cafe2fd065ca87f3a",
        "49ae3148b481bc096c4f92f1eed4ff297bb3c59a198d7d7f6512773b2b6cd991",
        "1ce299ac719c50bb3523342e62c35a2172122a617db6fbeea8ea59703831f969",
        "33742dca7842362ad052a62663f7d7dfecc92f90b350ae70b0b8a2fe83142116",
        "2bb5cbb00b5e0308d54703b14927e3e31dcaf7ebd2a02678d3fc00e527540bf5",
        "852004c180aff3c69920d3d913df21ceb642854c1c7336f1afcf99635a7df32b",
        "ea263e84e451e17ff77d642cd7a751757765aded33d62b96f1e998af31024e30",
        "62eab1d9fb46964dd85646cec67db99b5991770166d8c4c0d1f7f5eeed05f2db",
        "ac1386de9bfc350bca1d3da99c7c69b7799818a51fd4726790c52e8db2769b89",
        "bcc6ab14c78aaffcde1b37692f8b4fdee3cfb23150c831ef70844b0db368f7ad",
        "27ed257e9283227711d5a9ae7f59e107d74666ade82086f4708a9c5146d5d574",
        "33d01e1595d9d774f2030142af62b62dfc0805a478da3bcaa6ab3c3da168151a"
    };

    const std::string m_7000 =
        "90a8eafcfabc9068220bf96051d58a16cd437e931a4f098e0db7ddddc033c25a";
};

TEST_F(Blake2sTests, Simple) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Blake2sTests, ResetWorks) {
    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_NO_THROW(m_hfun.reset());
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Blake2sTests, BasicInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox jumps over the lazy dog", 43));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Blake2sTests, ChoppedInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox ", 20));
    EXPECT_NO_THROW(m_hfun.update("jumps o", 7));
    EXPECT_NO_THROW(m_hfun.update("ver the la", 10));
    EXPECT_NO_THROW(m_hfun.update("zy dog", 6));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Blake2sTests, Extensive) {
    int i, j;
    for (i = 0; i < m_cmp.size(); i++) {
        EXPECT_NO_THROW(m_hfun.reset());
        for (j = 0; j < i; j++)
            EXPECT_NO_THROW(m_hfun.update("A", 1));
        EXPECT_NO_THROW(m_hfun.finalize());
        EXPECT_EQ(m_hfun.hexdigest(), m_cmp.at(i));
    }
}

TEST_F(Blake2sTests, SevenThousandAs) {
    int i;
    for (i = 0; i < 1000; i++)
        EXPECT_NO_THROW(m_hfun.update("AAAAAAA", 7));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_7000);
}

TEST_F(Blake2sTests, UpdateAfterFinal) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_THROW(m_hfun.update("Hello", 5), std::invalid_argument);
}

TEST_F(Blake2sTests, DigestBeforeFinal) {
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
    EXPECT_NO_THROW(m_hfun.reset());

    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
}
