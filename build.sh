#!/bin/bash

clear

set -x

if [ -z "$ANDROID_HOME" ]; then export ANDROID_HOME=/usr/lib/android-sdk; fi

for a in $(ls $ANDROID_HOME/platforms/android-34/android.jar); do echo $a; zip -d $a android/telephony/ims/feature/MmTelFeature.class android/telephony/ims/feature/MmTelFeature\$MmTelCapabilities.class; done

./gradlew assembleDebug

LD_LIBRARY_PATH=./signapk/ java -jar ./signapk/signapk.jar ./keys/platform.x509.pem ./keys/platform.pk8 ./app/build/outputs/apk/debug/app-debug.apk ./app-debug.apk
