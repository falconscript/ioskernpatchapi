cd "$(dirname "$0")"

# Compile
clang++ -DIOS -arch arm64 -arch armv7s -framework CoreFoundation -framework IOKit \
  -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk \
  -miphoneos-version-min=8.0 -fno-strict-aliasing -Wno-format \
  -L. kernpatchapi.m -v -I. -o ioskernpatchapi -lobjc
