#include <iostream>

#include <toycrypto/hash/blake2.h>

int main(int argc, char** argv) {
    BLAKE2b test{384};
    const char data[134] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

//    std::array<std::string, 134> cmp = {
//        "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
//        "98e14bd264b8837ddf8fd12d6f5641d59c369720b02c105feaf99f1b6a7b9618",
//        "a99ea583af303d4ed21067cead52d67b11636fa6ec241f9f6cf5beda55844b8e",
//        "8d4fe9f5368ff397ce7444640f522f090597591c21392262138da6750bf1dff6",
//        "ad0b5f0ea7abe50530487c4d1f0de59699955eca58fa60372863927620bba191",
//        "ac7051c3915e46c4c5924cfadf0942889bda7b2cd2b628f6c5e56989cc8470a1",
//        "49854055f9d89a2a6dd1a98a6514135c7eb64fa6dad96c5cf9fd230ad9070c03",
//        "b913ba7aff43317cdd69664aea6b985e5f1581c1f6dd094a55b474d8304f906b",
//        "b4a5fa29d464ecaa8bc4374d3c693bf2bdc4caf23e9bd95a41a5618e07fa03c2",
//        "efa6be8c39474de57693fb05c37b8d042aeb5fcff0de7a400248d51ec04102ef",
//        "7718838cdc1c1daed92a4787d70b3595516d152c8fe20cac8b7f8c3fb5ecaf4b",
//        "c8a34b6ff4a2b9568e5075ecce59d4986ef8fea9278d9aa02873b67300bf0fbd",
//        "4fff9f161260216c4b44a83b1861d66618ef2b610388462b5af0c2d692838ef4",
//        "276c35942fb1222007746bc89ef6f017f179677e870e25eb2df763f21a197e93",
//        "914d90b6365cd17d12d91ad808d756faeed6e23fe1543982335bbb5e1d478630",
//        "4f89c5d92929ae95471dd1ea857bf896176c946ccaf639aa8052f12136604a44",
//        "5ff2cc0c8c601022b241c096216795e06bc634ef252e006d71f8940a55613229",
//        "e59f18c2d1e74f60d6bb10d28933b4512b7d506c8a0942516651db530f1761e7",
//        "c56fb65074c5c4e8ee116338bc4fe60c1795590d5e2ebb4235fff6991908e14e",
//        "8498aec99e0344f7352f8552dc7fb05fe1cf8c8bac667ba9a26afcf101cd47bf",
//        "141cea270b3e80fe396303cfea074eaa09067a3eba3d49750c057e74e101a16c",
//        "c4d372991c3662d2d575aae04949f608b3804eafa872bde75e0bdc49107abe94",
//        "e758d4f4bc135babf4cb817d13099ce3028ea88eadcc60c5abf86946bc9eb36c",
//        "6f69b58273c88399afeb3c07696b6ec305ec6093bc8c1cc041e101b185272738",
//        "0cacd9e7f6fe1e205795b9b9c9ff54048a96a09c0b749f402e73867c0c726c16",
//        "3e4fa972facd8978a058e64a800b965a4f29a987c866082c0eb23d021d2a8c5c",
//        "214f53ad5d1725c1d7f517869121d7215e07ccc4401f07ee69a4574ceed382be",
//        "c95318ebbbf07ef3f3f484b2776e463ee89893ec7bb3845000232c1497bfb970",
//        "5b58cd59e71d355bdab210c938ff5fcf86f6e89bce68d79bdb0a03a35f03b788",
//        "76d0ad86b8bdbbf6d3064cbd9846106d012d8eb3a90059a7b431981ed5a61041",
//        "f43606963e5390c621a47e7497ba0856ab5a328f1958fc63e83e9cb79eeafafe",
//        "52d076436c1cd79186d745fe70a3ad2bdcdda480ff817e6438f2b87c8673f4f5",
//        "58d07b9bbd996e11c020faa4b62a23f6eeeff444d3cba5a69d0f95189fa6ced6",
//        "f854ece6f634fe3cd906b2d2705f9324e549bfa52c0636e6caa0ab78193e7523",
//        "2159435f47c18551a9aee159760b39954154451d6cc426a8880247c362e86636",
//        "9d61bdc7aa36b0b0c316c350ba8ce028660105a806c965a604e3b695af2a90b8",
//        "fa31600a5d4fdea10c036943051b787eef30f696095a30f2809f171f3c27e5f7",
//        "a7953c71f6681b7fa68e8fa6312bf5768bb46033e758766d0f5c0cf3d2380942",
//        "208161a6f9f7504f9d5bb9f2716806eae10932f4edb860f448796f667362890e",
//        "c9faf51d5dbafa50feaa966071fff80fc31cfd1d3cc1ebe0b8ab18d8fa223706",
//        "a5940e37c95d66cf116f262c4c39b7da31e4c4cc66af979250a2b79540a2ca2e",
//        "2ba9d685549e52fddbf18351cd0c15969173d11e6aafc39089d47837478baae3",
//        "00012a978d4d24af0474d79e290e2f4d0dd7ea4fe780eeac25725e8a59191eea",
//        "b5de0375683b51f15b0bbf6bfbdacfa52f22f57c9ea9f2595c786af265850ecc",
//        "042100d0e90f66fc7129a97f0e8921f80324a2f3748e9ddf3a8fa2f9fea8b59b",
//        "58f8fbe88fd265fbe3239ef4e1591a36ed5a3f100b487f7cd2dfc3e38d6e6abb",
//        "a13b6e2080d6ff6147dc263a40b09198e6124b90ee52be2bce0fc69fa4169992",
//        "c7b24594d5c9375337f726df515e26ca751198ac59aaef8a636a3ea0bfe3e58d",
//        "f2002bc2615bad6b037e020c93d27cd3391b523827f05cec10f9c092c5c47e2a",
//        "3ad1882a3da98a7ae0e5c4589930fcafbf335d0d5eebd357d4a68bbb48c20e20",
//        "f87ee4ad1499b35cdf02141256ccb4caab90a2d6deb621c87a11711ebd90a53f",
//        "474836cc2527be8f0373ca4304283ee07feda936f161efc48538810435bd85b9",
//        "2cfaf7f14886a4f5d0e87b5276d0dee47deca80e033e3e0867abbb15251db129",
//        "b496f0f3b8e57bc6bd4af533708dbc07e1479532c188a066d19885ca11ff6879",
//        "37384df58412a8a97b97d7fbf91c9e36fc8b45496b65fa3967befaff65cf253d",
//        "612e6af78a48cce0ba83d42c1263f9b91c73d0691186a10d67fbc01275ae1294",
//        "1e58a5cb278908b848db3e6c2481b84a9cb701f2f3bc820ecf424d458b000807",
//        "aa877b8a27aaa5099be48fa67662b3f5b5061158572fefc4b156f59480346565",
//        "b9c301e38bc22076b2338103667fb3ec967163c6e0390fd1a8786b03f7ef9a05",
//        "529240fead4efcc0c81bb3a21c50bab9f3dc338e47d28d9e8a5fe3c9bca5b28b",
//        "356afaa7c790a274249e7931c86cf14ef5465218b2a50f5f0050c5055cbaa177",
//        "f90f672898e953c16f54824b898321ed748e6b8f1d9ed3f01b8b189838ec472b",
//        "671d3c590475cfb9c3974c605246aa0e90d9aa017c5e9b9b20ae69031bf6d107",
//        "eb2734c5ef4a1f1ff7bd2e7bc43ded50f138ca61ef8e11621aec8ac0ef307217",
//        "f85b88e0ac55872416d202c5f4881e7dbc9c7270542ef75074ff9b0a610b5a0e",
//        "65bba861969fcb5f1d8ec69e1dbd3e891f546b02203ce73b27958b9589a6789d",
//        "0adf0d75b75a6f338a0a0cd273e6a081dd5c0ab13ae3aa46fe79070e10f83fb1",
//        "f7a54794b8d201ed2e89a3fe4a1cde613a5431a7468217430ab8e94e5a452103",
//        "823e2f79a9328420d583cfed98043ad92b297c79620fdbe3e2d6e9d8e897e461",
//        "bd9c051073c2d621788a59e7585ee406dec42a8e1e0e52011e22654b89661d59",
//        "336d18e2484c7089de50741178c143533942a9969819d2ed5a2fa89b1480a703",
//        "3bdd2fde1b2baa397f92f5c4f26a73e31fc63e312448e257dcfa233a897f9e08",
//        "c4b49a77ee46b6c166d56157131d1ec182153d0004428d6ac011edc942becd93",
//        "d58b17f3692c3d419c61fb16531989faa0940427bd64136b9b44cfd32dda4a10",
//        "6eed53a1030f8d037dd9aa370bc4700da98d56faa99a5c8e85ac5397f6ec2a67",
//        "c9e71f2752c27b379f0aa90a328f0d67dfb77e2c6bb8ea4a8d0e8512aa143c80",
//        "306a2a151ed78025e952403d7fd165957343b13616b0d423c1f372faa172b989",
//        "4634ffb218bf141e0f48bd1faf9f0033525fc1458c4641234ecc0966a8830e83",
//        "b0590c80b2753d553aa0502b9a01fbf3fffeadd162eb7fbb942bce6834df7731",
//        "399eb1edddf3aff77569d2c818ed2f8d534bafa96a022549762b155812a1ab18",
//        "26712b2ccb5548453618d417a1c9d8d1c6fe132e748d58d647e2c28ec1a16b75",
//        "2cbb7bc641355bbab41c938941cb9003c26fc8c13eea972526a6a0987c2c674d",
//        "b8f6b0e34cf0565aca12517f9dd062c3a3577591657b78b71944772e75806d5e",
//        "e3302fa4084ef274105a9c7b2311e2b7bf16868d98854c449ac0bd7e1496fcff",
//        "0357f77fb1bf27fd12aea8d76fa08dad56f0e9ae5a79ee3055ef69af502cf5d9",
//        "c0c87673c4b5ffc386637967a13def30f4b48025f548019d03f296a1e47ca970",
//        "2e18f57039347c24927aa761b2da90957cb52f7720c4aaffc9a63035e23aac94",
//        "0c3d74524b25f5e3973e030556bd26580dcf1493e90f3a02df9a182873f22cf3",
//        "4967b8e85452998ff005ff5631b4a011367e41fdaf0043195513e681db20321d",
//        "de20ed8a5f886498c1014537c4886fedb0e1b1027240fa3ea958a745930798c5",
//        "f21bd8117448c0cf02a06f106836d8ded9a11988c9fddf0d00e6b1c1c4fe27c3",
//        "791e90fefc6f104b704e9ae50c105c3edd767e93f297d96238c41dd7d34d7bc8",
//        "66524cda987ea07215fe2ad166325eb408c2f9de74f5ee8b3051a946ddcd6537",
//        "4594f336267099245d46c61635090dc40bc5b9691b6b27a328fc0060f969a54e",
//        "12781a375ac0d4f14ce4b01a8a3d7132b391b6d3d0065f8cdcebb6dfb227567e",
//        "f4f03246d34d6c531f1eb296a305a7f29d01367007e4e0508a736564e4deac9d",
//        "ade2938a6b8f740567ec10da7a57758c3cc044c101b8a8b14f8edd238423a076",
//        "c49e476913bc203102619ccf5a2a8636c1d9405ec44320aaca98dbf94f82817e",
//        "abb82e0b4fd69cc97ee99488d99f098b463a5df8336f219c895d9688e2260757",
//        "7b0986c072aeafc2ce58861b54ee0a0630c25704cc1657f686a2578d909b9216",
//        "ff079d11c39c7fe6231fb98fc130e00cbedd8c34afa0c1162890fa4d5f880299",
//        "789d4115398d3d0e433e9d205befa8cc683966d274e8b03d4f353e3a9d8dc906",
//        "060b3328ac173c2efba7f4d8cb3be7ed7a234d6c04fcc19e41a6543520e81bd1",
//        "d8769dcff061bc77096e8307439a9b1665952eda2bf21d6e70a3511221b71ed2",
//        "91373688d4131d5247778642e70084bc81e230af5cdf874e2e7f2ae62a1f710b",
//        "6ae960c688554208827a1295ea050b07199e97b37475abd0131e0ffafd2d632e",
//        "88923adf2bb60e0fa9a21e33c23261322757b6d1500d8db7217f99a182f5d107",
//        "0b9532b985ca9abe2a43551e63433b499d8bebca501a626f735c15a9899132ca",
//        "dfd841bcb09faf5ba2c91eb55464c4fd9e93467745a4f07d37904a1f82f4532e",
//        "b0285d20c8981bb15946a9d9c8444870a88e03c40d1270ace67dc4ced88f29cc",
//        "dcfda25931a1e0b2f075bccebe4940e900354252f6db9d27ec644e0bba64d13d",
//        "33ec7cfb7f0f3f6d491a3d6f065f9b02a970271210b8470f83907cf66dc9494c",
//        "c161c80dfc78a89c00d6209e44e39675c673a6422d45d5968fd2c710eb256609",
//        "096e055836803c536d126cb4745b78a855a917dd874e45f8b214ae16de8a36dd",
//        "26d0634b61af1ba7d261b22f40b703a26ff32ad1fb0d08db0ac4e79ceb7d48a9",
//        "b3118801efccbefccdf67fc28038e2d21f7e6e98966f3371db14cfd70cf3f284",
//        "a2da7a239371ca9a995326326981a8b7fd8ddc92b1bb88d65b672857b104659b",
//        "2a029d303e5edd512eefd856cee6a52cc5fb88d716937563efb7a40cbebde115",
//        "13cdcb5b3ef09c16866c8a056be01b2bb32977dde43309bb030c17d15ffce56f",
//        "2fb4420ee5ca3ac970fde22064bdadf308c6f36c3d31ee41529892ce637b5296",
//        "765156a4772daf45ba699cd4a40fb0a24bea2898efcf340d2345d08c7e23200c",
//        "46596bdebd2e0421f5ce4d62f49fb615b0c3d5f5fc9874303ac5229cf87c7db8",
//        "6e4c72443f2e8e75b3fa57abd396f95db27b29526947379cafe2fd065ca87f3a",
//        "49ae3148b481bc096c4f92f1eed4ff297bb3c59a198d7d7f6512773b2b6cd991",
//        "1ce299ac719c50bb3523342e62c35a2172122a617db6fbeea8ea59703831f969",
//        "33742dca7842362ad052a62663f7d7dfecc92f90b350ae70b0b8a2fe83142116",
//        "2bb5cbb00b5e0308d54703b14927e3e31dcaf7ebd2a02678d3fc00e527540bf5",
//        "852004c180aff3c69920d3d913df21ceb642854c1c7336f1afcf99635a7df32b",
//        "ea263e84e451e17ff77d642cd7a751757765aded33d62b96f1e998af31024e30",
//        "62eab1d9fb46964dd85646cec67db99b5991770166d8c4c0d1f7f5eeed05f2db",
//        "ac1386de9bfc350bca1d3da99c7c69b7799818a51fd4726790c52e8db2769b89",
//        "bcc6ab14c78aaffcde1b37692f8b4fdee3cfb23150c831ef70844b0db368f7ad",
//        "27ed257e9283227711d5a9ae7f59e107d74666ade82086f4708a9c5146d5d574",
//        "33d01e1595d9d774f2030142af62b62dfc0805a478da3bcaa6ab3c3da168151a",
//    };

    std::array<std::string, 134> cmp = {
        "b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd3244a6caf0498812673c5e05ef583825100",
        "35f80c3c3abaf37b07f3ba84f78a14b449e28988e47c7bb08cac23ffc2b669f5734ed6007e427dcda84d2467be8f7dc2",
        "05c998599062f139138fc6e0ef5458c8d996be8e84966fe160533bdd2792286f1b339579f24a3fbe4ecee2599c49a4b9",
        "9aa07d9caf17bff49747fc9488eb6babcdcd575616f85a91758ee50e6e49a4884bf6fb46b424e0ae669071ccd8cb1685",
        "39262ecf273808cf314358b4a9740cf121ef91427394f8a3d3010396abb12d1bef21cfb2a24e40b9ee557d503e1325e9",
        "c3d2cf169ce94eef098fd26f9fab6db3a995c260793699bb97e409d3534e82fce4634ef994f6832e78600a9b7891295e",
        "3d974a9ee07066b128b4dede74ac1aecdc68886e11465022f7854e265ccdf5a8fdee414542c36d1bf23c22cf255e77b6",
        "88c3311b695e2a1ae5b7175a40dd3a2cedde67d136075359995b560d985aa94cea719f88c001fe86c6de83386ea91473",
        "942b9eb6a564eee1271c18d6007f958c8f245d0c06f687b278dcfc8b37ddb6e08fb3113d500b39f552e5effa02408b8d",
        "f536040667a3f56fb2096a81562f016a5e9e525710db4ac9c8e69465c97b388680b4193b37cd5d82569f9d90dfc02c0b",
        "2d6e10d1004bc924115f998240ca7335d3e9dc368ce1616508f2da2416cc2dd486375ca15cb025384caa3300a7c26270",
        "d4717e65c2ff3ba32053b5d44fc225b8912a5fb81cb2444060322036d7a9ec38aec51f04399b12bbb4610887405f1704",
        "5526bde3c7d3e557852c443698d76cd5d6f9ff0058afb0359700f67ae69746b9d0b5f798dcae79845fa3519f51ecde7b",
        "b80a5e907d33d042254a05c5043c85307e5fc341ec02e0aaaa2fdd10cfe536e89ebd1766f62f5f2a7c05a1f14c354725",
        "beef43f2efee112bb57c07615075d1a41cb169275690bfc56b3a04c2599f4789ffeec86998cb7c84d2b6aac323e8e333",
        "b21032a07ae89d3a2000186e23e400698c86d0b5fef2544197926527d2c178fd0c2776bf681fbd727d4f800c8acb8a98",
        "041ce726562d39dd624fe7ff981c98f186000fb6cdc555db7b41bd2992718469952560ac8d76158bde673c0d9a7cb922",
        "583d77e69e6f26378210fe6c6fb5a3a22d6c480b5bc7f56f95968e85b2414f95e81d553feda053119c64ad3e5f27a34f",
        "1a9a736f188ef182a006a2a5110aa421426af8626d797037aa6dc929c22dc7bbf0419e11f092ef4ba517c2c6fbdbb62d",
        "fa3ddc1edc18c7c853666610a765c599cce16c894a3d20ab92216a4015e859e29c0e93c9dfd5aafb1d4ef17154ef3c5a",
        "aa0e2b2ec20d8ee1613a396a5e0c3eef311405d32153cd6c514ca41ee3e9c757add57185d85a76b7b71a5b3420ec4195",
        "1c02d6234f371f86b3a426aac8b2d07f1b435efafcd6155cb52be97cade1ffbfd4c6a2dd922cf930f826b5ded7a1f284",
        "039abc7cd2bbf911ff0a1c979d6069c8fe9edcea33dff35b75d82efac784f3a1ec39557b7a2ee180508c8bd5a7f44124",
        "55a0e989c7208018632d2624ccc6c4553ca1485d5307e77e423d45d6643a68e251e6dc45ad5b00c8bd607a8779d1fd87",
        "e9eec03b65af576d3b6a4c7dab09d85083b637c805a0f757c618669b59d94262183f615a7f99b4256089c8bda1a445c5",
        "986f85103d2e982da78657f56fcde2c0e1c6a96e585a87ad8bd6b0020a71adf7fa7a69d92ee00528ca435416df2804ff",
        "8fc61feee269f4b9fcee98c23e748abc4f47c0e93f05a09d6b7ef0b86b2d91c5f1e99d6c3e11c2dedc60e3b8af77a7ee",
        "5b638b6e2fdfd1c27175119f73eb1baaf9b824b04010ab78c2c502a3f4a895f16fbf0b7a94ecc86a64029f370703ef7e",
        "7daf4facf105d9ec2412531059b2fcc95e1d73251f591fcbc2d9c4887ea583eff9cf9e8adca59f3a506a62d96859fd66",
        "b5ad3d357727cbe5a826df052e480bbf933e4e47b510933cb6da002389ecb1fff62f9f41c1e45f8ca1876e4fa2bb48cc",
        "859007c6dd4f62a7f22488cc56d4e5c630b9885b1df247175f0244e13397a3c73ce22b29ad8cfcbd44a0f8bc7a5c1c93",
        "c388d72f46764b32d008ba99706ae7b793d623edd5579833c1778c6e7742f7344b5f79182210b884ca8dfc146f08bac5",
        "e735a2c58fa150b3d57c9423af50f4e25e701fa121653f34022914372682037281bc130c1372082c6ab8995239148d40",
        "7cd86d4f4b48d4a090bfa8e6585cd29ec6604908d5d01c74fa6eefd28e4af9033fdd1ffed11c881da9b02b482c5f4b99",
        "4b4bd43080ea50f4106c12a7bdb30159ee9809ef98ab6d61c6d0b2c16653caf658199a39e5dc1c13cc6f1ced9f37ca4d",
        "813964585b4a1aeafb3aa962cc791c2d15f8d38d2df24e9048e1696f918320f82a4b64aec5f594052a7dd4b0c79a8b9a",
        "5ce1f8d92a54edfaa49a5b802e7a6fbee1d58c59f3bbd64af40483267564e92298b1e7339e3fed2f8b666a643d0c82e7",
        "6f8e2f041ea6b71ef2a38f9299970b47235f761f7e2c93966b0ad613be4d560229da716221a05d4cc47cd0d1923ae2af",
        "42009473489015b0be575326cc89f6d1d386b55a3e732081ed90effc4fba14810b5f6a7f801bb67de9b08115826c5422",
        "77f7ea1f1e811aaf715743f235092210858ad50b1800357535e303b748677d952a3e4f3637cc88a137d46be7268186df",
        "5657a57cf3d42566c7aef24ec792f8782a96ee888ca8fbd0459d009e3feae12ae75a4a039dbc6976c68491ad0f912b2d",
        "5437bda86ba2e36bb66431f7b3ce4efa74e23e0de9d4b326daa958b6718d410a54924f3612b74623a89d67b042e37818",
        "055f7b6029572f08b73408eda2b49341bc08cf482b4bc1fb6cb8a60cb30408b6a832224888a5874782142fca8feaa2fc",
        "230fdd15f915e3e59331b1ded4a54f443cbc21098aa87588670fc7de2837aae25cbae5c0c331dc042f8b43c862e7e3c4",
        "27f2bc86c7575f0d63e93a0078d3d40abb83c7fb6f794ac7de2fb31de1e7aeb688bf65ad4eb580a0d9154c57b59b182c",
        "8e640018639c7b377853587f16192787ceb7bbb23ddea2be6582712430bfd2dc022ff3c318bda3540aa464f67d515128",
        "edd566b17267a11860eb484c85be5b84e8ebb7d38996141f4022ea005eebb54d534b59ea37738449c129c036195355ea",
        "d959e677062c30c2cfc7f9898d2670bfd7c425b737a1d2e3cbd6f83ab38ba552d0cc4669bfa68c48c976467c2c365368",
        "f1f28512746cc7b0a312d5b97b5eb12b0f869e8cd9f6a23d86a0db64a38693cbf4cc3eb020a376a52eee9c91d310f457",
        "601918b6fd0c7921da7c9b25e9da909c52e76ae74ee2f19e1e9b3c3aa74e5c6bfeb0ecf25b67407fa22129ab93d043a5",
        "606ce4db4d7ba4e239b47bfdc4cc04b097cf57ec651f512e30c0641210bf94f2b7a186c93ce315e9d22ecdd52f6b870d",
        "3757555272b70aa49ba59d23a946f0b0736a099737d21e63be6be13f2ea73b1183c5906d69910e271d4d2a9254fa4ca0",
        "de60eedb06b1df8d1ef9af4599ae9dd33b02308f8259dbd995f2c8ae189e200105486b391a320051e2df6128e1e33c21",
        "6edbe8efa5d4fa2cc411acf32ee86c9f97934d417a0964692b5fdfa0380b3b4cea1cf0cb84fc8c2c3d885ea3c11b00a6",
        "0728ab2befb2561f45a014d28fb238f2be452f36a5070016c288795c8e63baf0c18859209f158cc58202d252f03b9300",
        "f734f2a9af1a4d089460fea94eef1310cc196d903e8f3b777f8fb7e8e111775b689ba89cc2b49e9930c2134531b3fe9a",
        "98399b0474bf51cc8fa1cc68ad568803e75eeec0c1086510bef268cfe8b81308dcf1406c8e6b5a5f12a469f2a08735de",
        "cc07623ddd8aaa2660e93c8dbba4dd1206b8042b9226bd761a95f066d988e3b3ff62b5f1689f800ff099eddfe92ce8ba",
        "1bfba3dbf278bf6559f1f15d27343db8e1b6b7bcee1696ae9acbb313ace5bc3587a2d0708e16d2affbd7d0d7e9a9faa7",
        "f99aa6c08f918a76fad541ad1db1dd70291307efb2b46245e7e4020b8cd76e110f5dbac208c2fd2963f2bcbd01221036",
        "2fafa343ab6c2099f545247ccf5a00d14a5b2a5bbf9827c07307524fc9972d07d931d6ad551eadf71bac94945ce74a2a",
        "f7dbc54b4e0016892aae7248bbd82199aa21fc196bc752e0fe124a591ba6ae3173e68c0a51aa4ed28158eac48ff24f7b",
        "85a5eb3f5ec3ec42b09d3afa9c1793cc421ef75f4985d7ea823e199b8d1907d1c76e94a42d0a5c1d145418ae1fbf9dcb",
        "68ec34832ce292f1b6400fb67ee7113e6aa7eda1772e41c9701a071085fd9cfe9e1faa1d15125ec1a9de327921b015d6",
        "3f33abf2c582afc41dd5baeb09ea6f65ea49d2c420ff3eb7f926464e7420c7df652abdb6f2de21072db971f5a412ad85",
        "734d60881b7ca9a5cc2bba982a9f557937f85ba72bf7049b19245dc02f56c752005526b62a38ec7372e5cf0e6d08f9c7",
        "e417c82c7072e41e7d05e8ced2f50a332c7b3ec614f7c4921f8514729ec9bc0ecd3a67ce1348c6b98ed962406eec46d8",
        "2da403cd42c1bf3c9812dae7360345e777c5ca09afa7f872ba38c70ada554ca7b683869c32db85c6f4e61a0c470534b5",
        "939e2a091144c2ed67c9a573fae6f29cf0336fe3e7f4b0881ad1a46290d04fc2ef31b707529bb5474209ef652e7a0b36",
        "e37ae2fe7e4152663940656595815e88aeacfa22fd386cfe95484695505c37d9a1377d607d5638fba91b31362d222398",
        "f3c5cfb7116ad140ad358fa474270e15f5e09532886bd065b7ba44eb03956d93d2ff245bf00f10395d61f88ae573b835",
        "f7ce566ee728672e8f2f6a7c369169999f4e04d2f1597b8cf4067a534d056e69775c623d6fdb18963d8333669a00ac93",
        "0053f7c54cb0f3318d12b51b05d9d46fb6ade7a95929e778f7787a7998676b9288060a2bb5d40b8a82dfce3cb3329434",
        "bb422f80b601aa8a1206032b5985c0314222d2ce21db4e2bd4f1ded870542ac47ddad7acdd33ae83d322b249a7a95f48",
        "dd6b5f1ab1dec1edac3fc09b2e6246df6c901143ec62f7ccb7f66b286f3a87235110c0ba73166b095119ac2e4b54efae",
        "52deb8c2db7fae5b0c82e2932f1f0ac3dd345e17f9297df8c6688a89bf1954dd35c7b941e2fd0e44692619453fb9ad53",
        "c045b2845804ab6fe9c2b1614bb21f4c97fc747a9081ab70ca0780388d7edbb97be339a2adafe6307d941292fe4afbac",
        "5a6ad2ce0bda47bb333ad25b32c59f1eb11691692f7fe9feb9711269a95aa6ed95c26455bf1150a330bc3916704e0a6c",
        "3ba43454c16dda641b0aa67693d788052ff94f120bb63c7a4ed048163917ade974474eb5ea936eeb4a1fb3d5f3a5019e",
        "7862f858dd94e691ad275be5c42ed4997029240cd8cec56a29991f4f28489f684b30049487189de0b5b5dbfc96ff6b12",
        "a89a6bdf662910d5a672c92210f4d8d47e50ef6f341fe8e48a3d557fff311e47b88401570db82aeaf2415498687bf4a0",
        "4b7090019d982819d4014aa3e9ad6a4ead3a8632adec5b97835b817666d6cbcca53ede60538ec2d2555f492c96f07b94",
        "431a31ba341dda7a8f7cd460015dc091883a39781122d20b38f9370b969cc1d60fca27e536e5ed73310e5f6b983cd914",
        "9c8bc86c45fc2141b76e8212c653d09769897b7522c39544defbaa0ccb5f33359582921ed1f959db569d0af8f32f346d",
        "f37e8b9df97c85403edaf00b26f2865d83cee95810000b8397fb5298ba14348137ff74cf81c58a3b7bd80e0fec3a2e35",
        "8a791d400c6011733dd80e28e6a84e85a01b459697fbc76590ff5a45392fed51f111c59d40ee5249a1379e0d2db9ab79",
        "a26ee463e7b44b6bb1ec508ad05aef171e43917cb90aa1babb542020aced663d98f33524127cbe5e24d21dd496acf5e8",
        "3c1581272f2c490c5ab23e6e10e2f00c6cd82bf987a7aac2bf6f4c40dd689ddbd33793a8013297fafd82f314ea828789",
        "37e9017098e0bbb194bb3f68c8e0fc5ee3c9bcc3eb30082fef179f7e2da9b58868a9a8be4212fea7f081947a800dc1c4",
        "aefb551dffb3bb03e2c9aeba895efe6dbdcc10c8d6074f9d3aeb747c008f0e14380639b12cc8d7fcc78248ee6c5447a7",
        "a10b866c59368916fe3be30f4ba7abdf0201e8e884367af148f535aa2c95a7ef07fb2378b49276b62a0c7d856af44d4f",
        "cd3d1e523fd5a895f37c0609e91c2801f95e12e411ed60f5a3d6dac0a82ac897a66adac359e4816def3d2c76a16d7aae",
        "7409720ff2338a8decf1c668653a28e4765423e204519adc3c55ff0e12e652b46740b8a4b9670917c595f19f2071df34",
        "3761d6880705318cf51489cf90b80a08906743a55c17164176df7e0203e8c35ad07cc4e07f72b6f845db56d8e82d7edd",
        "d47064f9569b25ab2b1e5456cb8ba86eeb520ee2df7b4ceb73b64a1825a160540a56e0eda450ee90ce77482284217ebe",
        "3ffe05023adb4bce79ac48a15aa9d1642ebf5fdcb2a1af7fc0432c8af7a22e029183025ee62fb3e4a59021823b298624",
        "45fe40e3425e5fd8b04d18c2e1d12b512da39e4c682a22ba21bf055784968ac22232f557af84943a6abc8cad63670d49",
        "d28c6dd98c4f40020a910dd778bdec69cf59e6368d231ab783960dc66503f8a7875b940b6e924066376620d1716f7d19",
        "b5b71295acd431df49aba311ef729cdc361dab7b5bf6fc363722c00b71a5326ae51d1d7bdf404b4866d7e31c5c4f718f",
        "57424045f8618081fbe3574e0662011d67d465b3a14346c47f7d3fa75124eaa132ba671c55e831acb15a9359f5508a5c",
        "e2eb20cd3944b981fb032a57f57cbe19deec7adb746574285217b907fab393e10ac4cf518917e65579357a2a88d57746",
        "8ae6ef760bc591f35b50627c4d1a7568feb5705526ae0aa2f0088f16400d523b200906c809a6817d4b8e4c12b12c6f67",
        "16bcb927dd0dea74fa20f448850ba11f9e5e160af474b0611c579851771f4cb06f6d6e7d7563529839726ea1cf2f9a22",
        "d6271695e99b58d81bc70f479da3174164780abb2d56d13d617c98fd7edd50618382fe466e4c2263a1123cf07981da02",
        "2db7c157d18f51d257ef7a14d45d82845bee740223bfa6128437facfdac3bc09f42e122ef988a8fb09fe8abb8538346c",
        "18e667ac79e08fb3835727edb065c0b733b3e449ec8e9bbcd557d7b7ab45feb80691cecb18fed99504bb2d83e8d2999e",
        "3dfebb894c714bc8b1fe2bbb3ee04026f7fdfebc5c6e0bc07376da7fd516642a80614bffd969a4c301e5d3b81f054b88",
        "8ef8ba14e1767d1df5c520c66d7e6d7c2a3b9807eb4753ea993f212721f6f594f4b0eebc43711aedb48934d25e85e12a",
        "3af56b210599f453207c6b81bbd9f29facf4c67866ed8a83617c6be159812ef8fb6860bd975adfde8739f5a3a2755549",
        "06c1d635fae33115995d76fdcd12d4de12d0227fc82a328439d22cef4f596bdc83da3a8798bc67808fcec2e4a43a4843",
        "791e88f17044c998f009200ba38c837107cdc6fe9b08004781cd7a3a821e625e5533e24c987cd03b4c7be15f93e86763",
        "9c844723fa125ef61dd3c02ccd10e4d1c4818a792a9aaa9104fc8070f851307d9497641c559bbc807581da9f40c4a5d0",
        "ce1a0b464c43fdd54c8d42862c83695c7a0b1fc20de7e5d3b72dd3518b0fe5531afa150a47733cd5fee9deb8fde8e306",
        "7a16efad7bc03d729ce5957fa40a522ce0f5b96d1deb91d53d7152d3210ab3b53ba04f68faadb524b4d678e9358ae55a",
        "10b9b2731a8e13c56e4d1c06f530c81e348b32bf781490640cd3cf8f2224bdcc942c99d1eb91e56000e9257f2c2e87e3",
        "5bbe16d01fc94d30352729329698bf74487fd1359dadf0b2d6fedc1208109563ac15b7ed55c2589c98964dd5b5a85a44",
        "7077406c15214f28729b616d688d5a1045f8f97b19f98d714fc467ed4c8622c7382c8f7cbf9ffef8ac078bf7f7772fce",
        "dbdc93af501cc493a21e1e1c6df92162c2f13cae790badd6f13f8be23120414294fa1e0a637c337465d8e0602e25f72d",
        "36bbceeaf80eeba4753a839c30ab1e0265d964f629f1fb3ea5200fd554277213f5d4479aacf2b3f22a4d1a8108e48ff4",
        "6d38d2e308a8bda3ecd6596ad1e42e0b38d4df976a883459572df83f82b815d0ce157dab050b8efca784c843e08203d0",
        "2a380e5a53a3f7dab8148d7c7a11c53f101bdf7ee31e2af3a9908b7f8fef332d531b453d2372af0b23a9cf838a06ad76",
        "25861f72062d15502067709512cf8c1312fa9c7a8f9b9bf30241441a6d048daf6b5fc6e7ab70f9292a30da4666f8dd31",
        "81e053be48cedc5f1edc1732d33bca906ccb081a0760381977d3da76ce62849156f96445c20bc3e39b36d7282d1b8809",
        "a89a1c8e7f444ad38a8e7163886a253c2d9c7c6b6e4aa16b65fdbbaa99b1bb3b85d7ad08a29d4c78cb6acb0ea25bfbab",
        "c02d72eeaf0a0044aae5c0838c4ef6e36437aeb10bd33d0a6e29757565ad72948b47cf632a6778542330cf0af3ede622",
        "88989886c523c4ea18757a0c63e6c6353fc204da0324216c0c472ffe2c14b5c9b729b1e7befec5346529df4a1a4eafc5",
        "b54bbfdb1f49bea1ba625a8b2d421992e84c4bc75b6f0b8b1c9f02630256fd767234d5ff1d0e7996e6d26ba2f22f6ba2",
        "6d907aa4aafd23eb8344af64ac54a59faa571e49ca60d9d31c5d03c0ac016557c2c01e1bd9c2a1f33a781878fe9747a0",
        "1871c64526a48428f28c8019f9b1a88198e2b67da06e6c178e221dacfa40c7d15fb1ed0cc8e0a322e12fc9583acf6917",
        "0f07d62cdd031e0d536691845ced548ad0a424ddf5db7cae8b61584af7809c5e53fdc98679ac1d4fb6bb589243d32b24",
        "16eaab33c11f9fd92f1a85d29826111c449039e6d0aee7a3dffbfeaa756f6f1a990a695ea797cd029c5c518a8b7df308",
        "06fc5133692efda605afcc93e53296df0910ef6f06f2d6a3227c618ffc254555bccb7a9622865ba982a59dc1a178e56d",
        "6720cfcc171b078cd4bd2bb15c25ead2ea706df0a6e307ac0e49d0c21d3cf656f6f295bc251a5d0b6348781bcd3a97f7",
        "e5d512a51cd0777b386b0c0417b03202a159f55d9e5e6494186048c70802c720dc1b556dd141b13ffc3b27577fa2d4da"
    };

    std::string dgst{};
    std::vector<int> fails{};
    std::vector<int> succs{};

    for (int i = 0; i < cmp.size(); i++) {
        test.reset();
        test.update(data, i);
        test.finalize();
        dgst = test.hexdigest();
        std::cout << i << ": " << dgst << " ";
        if (dgst == cmp.at(i)) {
            std::cout << "OK" << std::endl;
            succs.push_back(i);
            continue;
        }

        std::cout << "Failed!" << std::endl;
        std::cout << i << ": " << cmp.at(i) << std::endl << std::endl;
        fails.push_back(i);
    }

    std::cout << "Succeeded lengths:" << std::endl;
    for (int s : succs)
        std::cout << s << " ";
    std::cout << std::endl;

    std::cout << "Failed lengths:" << std::endl;
    for (int f : fails)
        std::cout << f << " ";
    std::cout << std::endl;

	return EXIT_SUCCESS;
}
