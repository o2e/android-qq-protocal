<?php 

require_once 'Coder.php';
require_once 'Tea.php';

$arr = ('ffd8ffe000104a46494600010100000100010000fffe0022323735313438663000124632ff7f00004c124632ff7f0000ff05420000000000ffdb004300100b0c0e0c0a100e0d0e1211101318281a181616183123251d283a333d3c3933383740485c4e404457453738506d51575f626768673e4d71797064785c656763ffdb0043011112121815182f1a1a2f634238426363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363ffc00011080035008203012200021101031101ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffc4001f0100030101010101010101010000000000000102030405060708090a0bffc400b51100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffda000c03010002110311003f00ded475693ed22280954539de3a37e3d31839ab9a35ec9790b190862a7ae39fc78c7a554bcb25bdba9141313f545dbc300707d39ce0f5f4ad1d3acd6ca13185193c961fc55cd1e6e6bf4367cbca5ca28a2b633192cb1c29be57545f563814914f14c3314a920f55606b235b1f69d42cacf9219b730f6fff00566aa6a56ab6baadbc7a70f2a671ebc0cf1fe35939b4f62d4533a6a2b060967d2f538e1bcbb6922963c9691b853f8d695d5daff674f716d22394524329c8cd529a684e362e56659df79975705f0137aa200d924f3fe7f0aa45ef6ce1b6b86be2fe7b282aeb903355920bad427965b493704caf9cdf296cfa7a5439bbab22944e9a3916540e8c194f423bd3eb9bb0bfbb59a611db7da4a70db1b00724803db3bbf3ab635e592383ecf6e659e5241883e0ae3df154aa45ad44e0cd2b8ba8add72eddf6f1eb8ce3f2154ee2f5ae2e21b7b43b64fbe4be400319c63bf5e9593757ad24f729716db1880c518eec1c0039ff003f7aaee9ca12e4b9976bb48c4ae03024e79e395ebd4d4f3f33b21f2d95cdca28a2b6330a28a28033b580c96fe7229257a95ea30720e3b8079ff26a5d2e77b8b259241862cdcf6233c63dbfc2ae5430c02177d8c446c73b3b29ef8ff0a9b7bd72afa589a9be626fdbbd777a679aa1af4b2c3a5c8f0b156c8048ea066b35f4968ad60bcb077966043924fde14a5369d920514d5d96750c3f882c11f05402c1475cfa9fcbf4aabe20532eab6d1349b54800719c127ad5ad3e0babad4dafeea2f282aed44355c5aa6b1ab5db924451a84565fef7afe86b295daf5668b47e86cdd5a41770aadc8dea87771f4ac3b0960fed69e3b004c334581c101481df3dbfc6ade825a27bcb2918b18df2093c907ffd5fad56d36f2df4c6bcb69d821590ed20124d36d3b3d84935743cafda7c2a162ea98073dc83daa77c68da28108fdfbff7ba963fe152e8bb21d16379080b82c49fad57d61d2f34c86fa1ced46ce475c1e0d16b479bad83776e97322059ed2486f0062e1b730eac411dfea335b3059c579a945aa43cc2e3254f50e38e7f2fceae5e4b6d6fa59976a346ab98c119c93d3f9d56d2edc41a62db4b26c9ae43301dc6476fc3142859d81caeae624fbafafe795994867daae4e1303dfe95afa55bc96f8d827552d86ced23dc301fa30f51dbabb4008b1bdb48816e6d98838ee0f7fe7fe4d6ac70c7116f2d76ee392074cfd28a70fb41397424a29296b7320a28a2800a28a28020bcb68ef2d9e1947caddfd0fad63c6faae96be4880dd40bc230e481f8735bf454ca37d4a52b6861ba6a9aac612445b480fde049dcc2b5adade3b5b74862185515351428db51395f430f4e916df5bbe859822b9dca1f824fb541ac41610ac890ed37570c075cede724fb56bdf6996d7f833290e3a3a9c115045a158c68ca63690b756739359b84ad62d495ee41a8c62e0d9d81f9885dedb4f04018e3dea2801b9f0ac8ae4bf961b6e392307233fe7a569dae996d692992253bf1805989c0aad2e8edbdcdade4b6eae4964032b93d68717b8292d8cb37cad79692df6f11c3102b85277b7aff009f4a7cb2dd41a926a92c6e9039da548e553a73e86b7eced96ced920462cabdcf5a9e854ddb561cebb187a5389b56b8b8b40c2d645cbee18f9bdbd7ff00af5b94515a463ca886eec28a28aa1051451400514514005145140051451400514514005145140051451400514514005145140051451401ffd9');

file_put_contents('a', hex2bin($arr));