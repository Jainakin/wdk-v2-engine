Pod::Spec.new do |s|
  s.name         = 'wdk-v2-engine'
  s.version      = '0.1.0'
  s.summary      = 'WDK v2 Native Engine — QuickJS-NG embedded wallet SDK'
  s.description  = <<-DESC
    The native C engine for WDK v2. Embeds QuickJS-NG JavaScript engine,
    libsecp256k1 (Bitcoin Core), TweetNaCl (Ed25519), and provides the
    native.crypto/encoding/net/storage/platform bridge for wallet operations.
  DESC
  s.homepage     = 'https://github.com/Jainakin/wdk-v2-engine'
  s.license      = { :type => 'MIT', :file => 'LICENSE' }
  s.author       = { 'Tether' => 'dev@tether.to' }
  s.source       = { :git => 'https://github.com/Jainakin/wdk-v2-engine.git', :tag => s.version.to_s }

  s.ios.deployment_target = '15.0'
  s.osx.deployment_target = '13.0'

  # ── C engine sources ──
  s.source_files = [
    'shared-c/bridge/**/*.{h,c}',
    'shared-c/hashing/**/*.{h,c}',
    'shared-c/encoding/**/*.{h,c}',
    'shared-c/bip/**/*.{h,c}',
    'shared-c/vendor/quickjs-ng/quickjs.{h,c}',
    'shared-c/vendor/quickjs-ng/quickjs-libc.{h,c}',
    'shared-c/vendor/quickjs-ng/libregexp.{h,c}',
    'shared-c/vendor/quickjs-ng/libunicode.{h,c}',
    'shared-c/vendor/quickjs-ng/cutils.{h,c}',
    'shared-c/vendor/quickjs-ng/libbf.{h,c}',
    'shared-c/vendor/secp256k1/src/secp256k1.c',
    'shared-c/vendor/secp256k1/include/**/*.h',
    'shared-c/vendor/ed25519/tweetnacl.{h,c}',
    'shared-c/vendor/ed25519/ed25519_derive.{h,c}',
  ]

  s.public_header_files = [
    'shared-c/bridge/engine.h',
    'shared-c/bridge/bridge.h',
    'shared-c/bridge/key_store.h',
    'shared-c/hashing/*.h',
    'shared-c/encoding/*.h',
    'shared-c/bip/*.h',
  ]

  # ── Swift wrapper ──
  s.swift_versions = ['5.9', '5.10', '6.0']

  # ── Compiler flags ──
  s.compiler_flags = '-DCONFIG_VERSION="0.1.0" -DCONFIG_BIGNUM -D_GNU_SOURCE'

  s.pod_target_xcconfig = {
    'HEADER_SEARCH_PATHS' => [
      '"$(PODS_TARGET_SRCROOT)/shared-c"',
      '"$(PODS_TARGET_SRCROOT)/shared-c/bridge"',
      '"$(PODS_TARGET_SRCROOT)/shared-c/hashing"',
      '"$(PODS_TARGET_SRCROOT)/shared-c/encoding"',
      '"$(PODS_TARGET_SRCROOT)/shared-c/bip"',
      '"$(PODS_TARGET_SRCROOT)/shared-c/vendor/quickjs-ng"',
      '"$(PODS_TARGET_SRCROOT)/shared-c/vendor/secp256k1/include"',
      '"$(PODS_TARGET_SRCROOT)/shared-c/vendor/secp256k1/src"',
      '"$(PODS_TARGET_SRCROOT)/shared-c/vendor/ed25519"',
    ].join(' '),
    'GCC_PREPROCESSOR_DEFINITIONS' => [
      'SECP256K1_STATIC=1',
      'ENABLE_MODULE_RECOVERY=1',
      'ECMULT_WINDOW_SIZE=15',
      'ECMULT_GEN_PREC_BITS=4',
    ].join(' '),
    'GCC_WARN_INHIBIT_ALL_WARNINGS' => 'YES',  # Suppress warnings in vendored C code
  }

  s.frameworks = 'Security'  # For SecRandomCopyBytes, Keychain
end
