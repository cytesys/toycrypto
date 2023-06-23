#include <gtest/gtest.h>

#include <toycrypto/hash/blake.h>

class Blake384Tests : public ::testing::Test {
protected:
    void SetUp() override {
        m_hfun.reset();
    }

    BLAKE384 m_hfun{};

    const std::string m_empty_digest =
        "c6cbd89c926ab525c242e6621f2f5fa73aa4afe3d9e24aed727faaadd6af38b620bdb623dd2b4788b1c8086984af8706";
    const std::string m_fox_digest =
        "67c9e8ef665d11b5b57a1d99c96adffb3034d8768c0827d1c6e60b54871e8673651767a2c6c43d0ba2a9bb2500227406";

    const std::array<std::string, 134> m_cmp = {
        "c6cbd89c926ab525c242e6621f2f5fa73aa4afe3d9e24aed727faaadd6af38b620bdb623dd2b4788b1c8086984af8706",
        "5927a32f0f0c83b9109f18da213e2a60fcd62f2544bfdb7bb711261f03b362182d941994ee5807c7297808c0ee23bcb2",
        "1f52159da1eff91af2db7af919af0da1aca9e8510431be530b5558005b3ca4923042119bd736a4ffada6c2971a9b5465",
        "f98876566f44ee8ee5a8995b5d6b4ec799a332422a14a342537e125916107cc632d9bcfa44694401c0aac01fffb7003d",
        "40c7a002d92c7722d21359fd49985be493e584353df3cda76b51ea7d8d0d10f7305b6f0c5ac6dec3f276fadc6e7ee863",
        "1b93804440be1a769bcc1ad1109823a8a29aa58b88a862be5e68e1a4abc97390870cfbc41cd644041c07b1477b181812",
        "cd1b0bc0dd16161928115028b13fe7c3a1171485f38dd5365bd80878ed616cb741d25307a4a6a689471c9c64e061738d",
        "0b546c89abcefaaf9fba6cb80d102c026929555e46eeeb30029779cce0349277b38454d9198f9a504d6e176ed1755943",
        "15925daf92e7766154637d9f56167d68eed1e01efbd962be3858a246e2124d2d77d04acb745d2f1d7e942cfc9724fd0c",
        "685fc4647b98e3d6d2415756e0e3b4c30ba4ada286c08acc7cb9f36f4d974b48984317ea4e768259dd90e4deae96ec69",
        "734d168ae04190e9e08f47ea976ab747a53c2944142c4242a8a1089072fd890af15d0c88ef8a371deef5bbba6ac9cd8e",
        "c460192977709eff76529d8ffad218d08a778f387369c893d8f16d9528a4de2ae46994be3bb9419792d43301a06ef5cf",
        "23fd16d93e8be255eb8634c01f5f870bf8fc1b4b979cb465cf0840d4f2c5f752cf97d3938c3593620d16e865b79aa3ee",
        "df2a6478080a0ee01536897c2bc823bbb7899b2f646c260926146225c76040719d2a348e97315199d6c4d888fc30feec",
        "afaa9c2843980011b206152dec0df3a4bc845e57d1251e7261b9fbb01de42067b38ea2bea7c187e1c288936834eae90d",
        "12e64301e51e051f0e66680efdaa2af8f1fb408325f584cf800373397037962232b41c56643bcab6b5d9bbcca78c99ca",
        "1d1e35f94209bcaa77fce61da26bb7dd5c3bd38eda81501a54c01e0319f3c9fe7f8193ac6ce9421dd9adb412febc2244",
        "bc56879cc5d8ea3268897ff9d966981d90997a84b6ada8c0b714a8ba62023acdc86e05daa303783b774b67879e63dd8d",
        "d6adbf3356171a6831876efabefab8f081e9dc623fb6c75a438386f336b56f3dd9302dc1736f32e1875ed9db6857c3e1",
        "27aff66fcbb11f3754f22e1d3646e3bd49fb438185e4ed91c5de0c2c299ca7cc33f207aa4ac1c376c93b0369af2709dd",
        "f70291894ecd5b5fcf3bc5ccc7f832e706c336aa4c56dccad2a227bdda6536ae6c768efbe7c864bbd8b3f11f9cd51dc9",
        "d7b291a5877ae587089ab5cc5e1b8f100a3c7125c4c883d17be6c79c144cda92b2e835db748a98b0f9534dc3d56059ee",
        "0b5c5e6782ad9b39dd305916fd9c3aa41b7da519c6b886396e64e737a890be58ff75ec442e692a8c3f4f43ddfb6aa3e0",
        "757c3c80641707d89a9c56d21c09639f009a594ee57f7e6c80eca6f145fa13549e833f1a1a6b05d0188f408bda2d176a",
        "493c3fb57632f4c91a30d0e31d3fe945429a11db68f446e8de29aa39714107b393a514705d810ccb997cfa09047e3556",
        "2d51182c399cefa1e1694351b8b14ad9ab01370349df80dd9a57bb2bf34b2709fc50c96069cbae1cf2422c21625843e1",
        "01b3924f277dda3119e1c6525ed879febe7dd4e0076bee036a0f79f044f987e2494dd8ec4d0f8720213996de7593f1c6",
        "26177d4222cd60501a6a6da039dcbbc4f418036f8a6ef7ffe2730f302931e26c67f02d552e003bc596e8e0724ac40520",
        "8a567bbb338e0db5ac7f4fcf4c419fe528506f2cb3a4078e35fcd8976350667f6b3f65f3698ba021ca5d6fc845ca7bf9",
        "2025e2db399c5d3b5db669ed53b7c63f339c48928977bf30566a3e9cf541d90f06cef1578a0f12ef35d81e07d75602e1",
        "79845656d7e19e8056d31ce5cda6ddd0d3d116876a7961749309c04dc6d59eea78e77d1de1a4d616f66a65204ed274bf",
        "16e15359a26af5328d4acf20ec56114d192bab6ffbc7f0f889658a1677be1e3c297556ebb8ff0893f425486b004bae46",
        "1c459ffd8268467bb11f23646de987aff1e4607c8b886c0434dd49923d48aab7e0ee87e1c9fabb436bf81d2a97312ecd",
        "797a9a6dd3e20a48d5cdcec96338f370706f228c1ab56f80c876eae3ec467932c336b2803953d09d8a0bdae789e85bf1",
        "3c96064987ec1052386cad03f18845153aab569c8aecbc48d71f5a61f68aa9397adc6df22c21d61b9e8eacdbbed3ef6c",
        "fd231f4f7bc2d735725e1026e0e2698338a811765e3ca52ff8b7fe277733b293de2a9d2cda6b736bf713e9a4233025d3",
        "3736264d8571e1bd1506ac483ae0269c8e5337634e2a6d95050c6d81d5443bc0de591ea018f41971b8d42de8d63fc4b6",
        "25a66b994549fbe3962db464250dd43ac1037f768407f7fe2730d7b24d4396cbe8ba47157f3248442a19a806fd35e241",
        "0748e8bf6f31a478cc6ecd605dc9378dda9afd79f4c10a69b9ec7997ec31dfafb762085b504fa49f403ba2fafd7610b1",
        "43e7a288c1cfcd58b7417c323d13aafcb277a209b63c5be7fd58ec03e68a52a667ecdb3da9045c93e05a4d8b87cfa932",
        "ff5ccf84e13c69ab2d1e57395fc2b7a02942f6dc708b042f3e6db4327ec2e9122272db3ca79f87216155f175920c06db",
        "9ce0489f7328aba173c7b2fb0b4518e5b80bca06d158cc7b4fa7bb048c7ab86b2cd5a2c85393c4702b50482389daf4a0",
        "fe95ec6256fe3ae6bc34d1974dfc891e7c08a8fb522884629b0fb743cf95f36ff41afdfdf232d2f5193dfed433621d94",
        "7f4167b4395addf03afb628350c0c84fc4be8478d647a866cc716dc56017d75d69d3fd55581ff0b8331e4bb4d00ff13b",
        "48eda3ff2bd44fa47ebf67bb614f38295703720212d3706400063ba5ee4b69bd142ed49eed694c1ef2adfb85ac359ab8",
        "5baabf46a3cc999b1d91f01dc33649f6cb121223e537ec00f9e6fdc74c24d185b5aa53834956fd8edf27ccc23153a0a5",
        "66e689ce40b8e0ebd7153491f3eed7173c7d4062f9b77ae1693df8f9863904f2f5d0fa371f4788c11e64032ebcf1c648",
        "69e3bf75fc247bd2bc759ad2d1232c21742e5c4b1bf11fe1ba1cfa22348abb689bb3e8b6320fdb2718509f4134f0662c",
        "0fe66a30e38b8f7296f0c9392740bcd32664ee91e69ad3b2dbe9aa72858cf91f011f1507da3fd5ee3c333ac91b6f5eb5",
        "ef24784c3b5385df96e7d1664a5b2470eb992fbe5357bba82ea84a356c9df1a06c5d5050fed8026f8273313369fd787f",
        "e8ea6f9ef66ef4a685a0fbd19e5cfee07bd96ee03f28a457167e66f652a8e6c48b4e9a08de25377864e4ae79f6334cc0",
        "c147fbea0b7f705b4b69e4e7fd579bd2aa09d0c6e44851d539c5f98c68aec6f2ca6cac6595ff8ce0a5556390fc5235cb",
        "cfffc353b08412900d6f994d7c0952c0a348c45f41f905080f94b7e437e38b2ce69f0bf6087720b054ef7a43f4eacaf9",
        "5af3a820de5677a3d36f9d3fe41d63d5668d993df8afd023b81c76e4d6f38571f885e3bfedee85f5a0a702efa7011b92",
        "6e882969feb3556b0bbdb714cfea27b520b96fe0d5b9d2c21dedb4af6966474cdb1cb97676d3302fa14c43d7525888b6",
        "10f3ab1ad85bdaf127593dca60cb7a6a0290bd9a6c405b934e9726cb3f85d55e4f8a7288425e14edd9d8a3561479b423",
        "2f914728db369c5eacda1b820612d4a2fed452bd0ba4ca6e59d2783f9396988a61340c9e66414600c0246c008fabacf7",
        "ab49565094e80ad14d874ab33287f121f474f17e0eb165473f9e4b7150e91d4a3b9e44c4af7f4f030f12490a2788c4d2",
        "942b935ffec6ad21c4f86fae726bf4ab5a5a2e2d9aec892dfce8a65b43429c584315f53e0e0cfe81eccdf1310b2d5f7e",
        "a8ca77fd274596ad1e0f5690e5eecb341fc8af497c8508f68720f07e87f8c156bf9361708ba1bbaaec433cfbf584cc93",
        "2b379104247289f967d73c31deee865019674c75da1ac0d22feb43e4c0b9dd5633670a23f6335ff76b8f57c3d7ef95af",
        "29b4770572465c8b9e4ec935e0bd94a7aa34bac6293eaeb1e0efa20a1759ddf236d82a8d6993c558edc34f6a752f1b34",
        "8020b82954f90ec2ed345241776171decd4476d5a43a4d469e14a52689e0f45178c08225db8c8e7e7b31d3967859afb4",
        "a5660450a938e54dddcf4bc290dcf590a946aa44a9f00ef92dc0ce34c4bfb5e1aa59bc7738e53ab10bf014720d4d1b24",
        "0a1fb73faeb675be20dd49cf199921b3d4fda8d4ed53fd1cbd70fed33ed70607ac4ed7fdd15557265e637d083053d831",
        "541763dd378a0c676858736425f3352d3694b1b60d2c92097c643d4d9eccf00f3ae44740bd2d2a9531c3a2873b9239e9",
        "bdfdf17083aeab4f0cf1f044872faccd221057e07f947891310580dd343b93ec5517f468d2465ea9c833760c07cde05b",
        "257b0a78f1e4e92f0419cdc4f51059c69288159cff93afee926ae4b39cb9af199f4e2b8ac8deed0660b944ce9c186908",
        "257c68be1d09a30d13fe9e8cb41931c7ef146ecaa64a7986c9973bc3b866f45ba8c56e26087d05116b3d362f66ef9b12",
        "552394f2e0f07e04c5c7b9c2a4d80d722d90363e8b32ad032f05aac6e682e5f224f887c0cec49c91bd9dfd0b8d6ae012",
        "9ea69f74dea5f9463819be4b12bdb693b12e0ac5668174d1b46eec1bbc08639ce95c660cbe5829acd4a0e6361e08855a",
        "f43435b0643eca15287f1a812c9cbd82948066c01f3e857f08941a75bc1addc02c2e9e0987774469540b067e15151916",
        "589289eeca6f7e0cb46e408799b94121a4aa3b8879de4a82f06678ccec197c02c7d97065157141da8f0f51d717041f0d",
        "d708a3092347495c16794f8387a3980b506114d406a4291ef087a6e03beb01e284bd754e384e1688f0047aaa946cf6da",
        "dc5fc6f786970d71d89e7e69a2968bfb567dea907e9a108b9c361421341a303049d56fcf95d41ab641f619ab05da9adb",
        "0d2c18fbbd828032ddcf05c6324711d3a0eca61911a4087751620695e41bb699e7838a8349db0e71037cec7ba776c32a",
        "e7e1e9fc530cf6756642ea9b9a16ca61b8fd9c2aad6b76795d840d12570ca57c7529cd7593015698626b6bc147be6ce6",
        "fd94a215a0c8ef6caafdcd35ffbd4b503d4eeaddb2524c0d856273740b2d9bfdf31e2a4235087691531fd8f478eb545a",
        "68db482587e2d07b17388c1c3508f21ee9f3b8154aa4946b41c6f6e545875feec8c685a0ce8cfefec177602b67a99ddc",
        "d0f863d7582317f4692ba01a1a521249c5ed992d9a20bab330ae0128dc8bc480dfe3470e3f6568a0107b618eef7a424a",
        "dfe1603869b8ab4bb4f4b3bf15d1f1613622814a7a898fccb0e97cf65304f2d9c1a634f7ca1d8f673a46f980388d6d64",
        "20ef92394da64f444ae4ce9d0de28f6beef50d0da3a42f29163078c77525fa096893ab2dace6ee0197d7cb7fa8c1095f",
        "e3b2185882fe3d43ea44439c3eff8b37aee1756c367fbddd72371da9634d7a1f5b00eba7c875c75b7c01fee0883ebd6a",
        "75b14d911101464bc0a1908126eca8b79acd83faa403cb74dd3e962d90d4ce3f77abbd66975a550ecb509411960c5324",
        "c971177c8e9a91c4871bdcab35adb2f98c38ab0c1e34dc8f8aa0a922d11dc8e868cf5e701cb6dda1a494ad6ba0404ed0",
        "237bf9e82d1b97ed27ee962116c16bcfd452593b51cd7d92e84be52ea09d7854274265fcee42870453006ee010db9113",
        "31e670dba6f2246329915b33798098aaf635f040f149de3d8f270f2271f4c43f7157b3207c77d49b5624ca842c9c5e04",
        "e1613342aacd7dd554873f6e0797a129d9beb0bb511ab14c1f59091321d89211780b5a51024df359bdd85d81c6885cde",
        "f723278476cb2308866151c459a31cc68a2a30962e6b2647a77e724e04e4085a05e844d32e8b635c38b20f932025fdaf",
        "81ccc85649dd68fc326affc8c9f9cf7a2ddd2abb67acf42b11a9b5a43ccd3b4d58c2b6e1748aa9eb6493197964cb23af",
        "447c384b2c751cd8a8681ced8e46c51cca9448e44b66d040f2b7e75a866fef361d93e8383795650a16650f4ec1f3eb1e",
        "73d94801d4ab35d3e802d38be230550f4d840b35226cf5fa35228083dca33a48bf8906b7ae004cbe7904950b567f07f7",
        "ef02f6ecf4979159baec11e321cdc4e4e6b5a01b91704bc75ffd560a1cd6a952c7154d2f7ce7020f3f42d9715d513a64",
        "4d5a2d09b60c4c7641d6d889cf1dce7fdeb6eb6376c0390c19264736da2d46d419666e5cd1d0cea0ca49d05b27f01334",
        "2a233a302b1c12cf25a527ce5ac7b947fa90878d94f8c25be91818b7150a8ecaf1ecc9e1b57b56ae401813ea4d62f279",
        "71870196c456d6c665b8e3e7fc0f33ddf9476e3a1dee0ed06f9cf7ff4fd89349252e6ec9947b367da3c35edc13e9486d",
        "dc9218489d47b2a9077214f688cd8cec42362ca5445fd76585b2df71c07a0121c3ca00146d6dc39571f9e81b344c5b13",
        "7937c38b45abed199255bd0cada689d5b0d53478bce58e2bec4f616303e3bd9d0e1e80895d16710c8665f5060e36a147",
        "0d14c1de1a5884dd645b18bd928ea52a510bc7416b4a72cd091dd5df41533669eea648789364709e364f80f48e4c51d5",
        "f6f1d06fa890ca8f36caa528b83b9a9ed2cf6b143ad4c37e258be13956a02af4c60fb25b62e2fdbd86af5cfc144f064a",
        "0eb7215c62090ca8e20993f8133460c3103f6fb1ac6be2ceb78a5f260a861433b9cd852562175527cc3f7e7f0f378bcf",
        "15bba54f920542a13323ee98f6ad21e137e74d7f1c092c7ee2d4aae52e6611bee2b3576ead567e4ba603781d805b04ea",
        "8c7f6c94c347c0ce3c3c66fc8e258f686dbf361165f02f3ddbcc651b65f7141c40e2385c78528bf3a3059d998eb589b4",
        "c51083d5fd2c0d249857704a21446f6faff23e198956324312ef395d3e7bd6294abfc76015df156da580baec8f601681",
        "c89d4de8ea8b5c7d0258c709d0760c3fa8af39938155e48c5d0524c2b629bd2fde83599606502432710b8f5125ef19d8",
        "4e572c07e37b6b74088d2dfbca4d5fb4ab9454f7c8bb8967836e416f97b5ba7d56378b0c1452ea903d1f0ec502e514b9",
        "c775d125dda5e1c4a8ab12bfa2e75e034ee54f8b0517e69b0b8a1c41a434fff7b290d22f7fa9fa4c470ef347109515b8",
        "06f5083cf1b58504f1a32d8c23b231b4d2e189a13d9ee5dcacf46580aa4e70d86e14f262b444c4092afd6540f87312c8",
        "defc40b409950b4f5a93a0aaf2f1a3f7c43cecb484dbb107d024bb14bcc1f92ee549d7fcd3f3c71a050e706baffc30d6",
        "8782eac472eb6b842bfbb5475fd9fdfe55c4ac49877e81ef30ef8589efca7c1b7bc1286f3cded38b80e70deef0c37b5a",
        "933291e8f1a4593a9aa71f49c64aa3257383b94f17fd4092607c2a5c7c1bd29e13c63317dc04c0ca378ac41942a26007",
        "57c2874232e1b96ffc22481a65a42029b03b4a89dc2d10f5948a67cea3605568eaed51a533695bc8768e30806eb50f58",
        "a33e0de255f23541a1fee95c61dd058e3858b2086822f603f569143c7d3613dc106ef7be872ad7a108ee65c417df7606",
        "9e956be26c24985f98984259ac812d0e45df1b7af0acb8e0c3261e3b58ab99f782c1f7b9e60b951d92541def52c05d8f",
        "f70119a5465d4b1f1543fc7222c29c6ac3e085d3c346c78bcb76d54d54357189af325e87f5df090c6f95134790bcedab",
        "ce98b08488bb1842c8490b0d8b6a3397ed9feaf6290aa46db49bedd7f2e367a47c902191dd848fd07435b3a475bf2e1e",
        "d66919113885d810b532821c1ec43d1c7ab75618c95086548153e7d6e6fc7b4917c6d827625e940ff2e63c5b873891c5",
        "6ac820dc95a3d4745df28a7443535d868edc474055a6d7ff2d61f241a3e5437f769cd9ee46cb416d3ef59a6b46f26ec5",
        "04a77d1d281b06dfd926ca5abc97c15c87e0a36d51bb45303c311d2bd9888424854546198bf4276b7bacd7ff7e3a6a05",
        "b055b0f894584aca319743990c33581d1da0843d4bbe04887a7dd9c2e8c886ecb9b6df03e06639e06edad42ab7578c60",
        "da402bcb7926b6db46236274b7dd73218c964ed46557dae0f45a42410e19ca14e430b84d48558872ee2641bcf1d53bc1",
        "2fd54a7eb66be72b5224aa6e0451b29cd2ae89755064c634e4349a0f34029c0eca04aeea2124ca79474d37ac0f3d798f",
        "02749b8bdeeb3d2c12c0115065eebacaf8020bca83773fd34b8ffe215ce62eaea893e8957308f7d436cad91424fe91f8",
        "e74d71183409f338c0aa9c9c2dfc6660f278d68493af6e146a9a79cb35f3c3c54291ea3bf952f2cf4af74f929baa84cb",
        "07be2e4fbcf37e436d459886f3f7d32e856a674cae090bb3fd5fd01b8f0a721345b917265023e3d4e1798c7ca761867c",
        "466b9f0e6467d4169a6fad852be401c39dc02d53b9570ebc9193b08ed5dfad963ebe9ed49a37d0196fbbe14b3ebed573",
        "0c686efe0166143c772d577662d116dd3198aff7a8d3064c3adf146396531a07e897fb4415285097ffca81b18c62d38b",
        "e35f4e7be84cb3c88d3b5762a8410698f00e839f7cc3f2795e82520e0ccbffefdc3f63c496413a3f1033b9ee769cf854",
        "55d26be0498e5a24c4924c9fe2ba8aa05a523aeb577e36a1ff1e7fa33e6e3f7e4bea91372e71eb2a42dade06f5a3081e",
        "5158d1a7fd41abdfa5d652b5c441d86ae3db3180fe12c136065b30277c78745a950a636b8dc749d97c322c2e2f1cd15b",
        "9635ec2043a748b0d94f37dd350be6c1b188e498a23ce40db6a41c05e95bf606400044a1b158adc36f23a7b0110d4da6",
        "6004aa20277b769462d60975719453db12f193184c63f58fe64aa5adfa74b380ea07a8447a7916016d6bb67d064acebd",
        "d52f3a7869c0f1849da71b45cd15c7d6b4eacd79340bf776bd90f476ed306ed8c35c7ff562bf416b4486b2c0bb836036",
        "a118a69b31a25fbd9ab7f309a446724a5b3ec0d70a3661d1ebe3b4e27e983fd3b0e73d12dac231b72576f5cbf819423f"
    };

    const std::string m_7000 =
        "7f0f8764a9a43e1bd1814423510bda84975dbc3370fe3d28b1c6496d3bd7f77b0581b9eabbf193436b8bcc2a024d8c28";
};

TEST_F(Blake384Tests, Simple) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Blake384Tests, ResetWorks) {
    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_NO_THROW(m_hfun.reset());
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_empty_digest);
}

TEST_F(Blake384Tests, BasicInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox jumps over the lazy dog", 43));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Blake384Tests, ChoppedInput) {
    EXPECT_NO_THROW(m_hfun.update("The quick brown fox ", 20));
    EXPECT_NO_THROW(m_hfun.update("jumps o", 7));
    EXPECT_NO_THROW(m_hfun.update("ver the la", 10));
    EXPECT_NO_THROW(m_hfun.update("zy dog", 6));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_fox_digest);
}

TEST_F(Blake384Tests, Extensive) {
    int i, j;
    for (i = 0; i < m_cmp.size(); i++) {
        EXPECT_NO_THROW(m_hfun.reset());
        for (j = 0; j < i; j++)
            EXPECT_NO_THROW(m_hfun.update("A", 1));
        EXPECT_NO_THROW(m_hfun.finalize());
        EXPECT_EQ(m_hfun.hexdigest(), m_cmp.at(i));
    }
}

TEST_F(Blake384Tests, SevenThousandAs) {
    int i;
    for (i = 0; i < 1000; i++)
        EXPECT_NO_THROW(m_hfun.update("AAAAAAA", 7));
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_EQ(m_hfun.hexdigest(), m_7000);
}

TEST_F(Blake384Tests, UpdateAfterFinal) {
    EXPECT_NO_THROW(m_hfun.finalize());
    EXPECT_THROW(m_hfun.update("Hello", 5), std::invalid_argument);
}

TEST_F(Blake384Tests, DigestBeforeFinal) {
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
    EXPECT_NO_THROW(m_hfun.reset());

    EXPECT_NO_THROW(m_hfun.update("Hello", 5));
    EXPECT_THROW(m_hfun.hexdigest(), std::invalid_argument);
}
