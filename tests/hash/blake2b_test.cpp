#include <gtest/gtest.h>

#include <toycrypto/hash/blake2.h>

class Blake2bTests : public ::testing::Test {
protected:
    void SetUp() override {
        m_hfun.reset();
    }

    BLAKE2b m_hfun{384};

    const std::string m_empty_digest =
        "b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd3244a6caf0498812673c5e05ef583825100";

    const std::string m_fox_digest =
        "b7c81b228b6bd912930e8f0b5387989691c1cee1e65aade4da3b86a3c9f678fc8018f6ed9e2906720c8d2a3aeda9c03d";

    const std::array<std::string, 134> m_cmp = {
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

    const std::string m_7000 =
        "375e762e672f963cf4447af23a1e5b7848bafda6ccc38b2eddbf4cade427073238e5121254cc95fe92dee635770c1d1f";
};

TEST_F(Blake2bTests, Simple) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Blake2bTests, ResetWorks) {
    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_NO_THROW(m_hfun.reset());
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Blake2bTests, BasicInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox jumps over the lazy dog", 43));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Blake2bTests, ChoppedInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox ", 20));
    EXPECT_NO_THROW(m_hfun.update("jumps o", 7));
    EXPECT_NO_THROW(m_hfun.update("ver the la", 10));
    EXPECT_NO_THROW(m_hfun.update("zy dog", 6));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Blake2bTests, Extensive) {
    int i, j;
    for (i = 0; i < m_cmp.size(); i++) {
        EXPECT_NO_THROW(m_hfun.reset());
        for (j = 0; j < i; j++)
            EXPECT_NO_THROW(m_hfun.update("A", 1));
        EXPECT_NO_THROW(m_hfun.finalize());
        EXPECT_EQ(m_hfun.hexdigest(), m_cmp.at(i));
    }
}

TEST_F(Blake2bTests, SevenThousandAs) {
    int i;
    for (i = 0; i < 1000; i++)
        EXPECT_NO_THROW(m_hfun.update("AAAAAAA", 7));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_7000);
}

TEST_F(Blake2bTests, UpdateAfterFinal) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_THROW(m_hfun.update("Hello", 5), std::invalid_argument);
}

TEST_F(Blake2bTests, DigestBeforeFinal) {
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
    EXPECT_NO_THROW(m_hfun.reset());

    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
}