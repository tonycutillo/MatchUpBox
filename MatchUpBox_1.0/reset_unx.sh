#!/bin/bash
rm -f ./dbData/*.db
rm -f ./dbEP/*.*
mv -f ./mypem/TISPKey.pem ./TISPKey.back
rm -f ./mypem/*.pem
mv -f ./TISPKey.back ./mypem/TISPKey.pem
rm -f ./user_data/*.*
