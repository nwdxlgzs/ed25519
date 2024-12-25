@echo off
@REM ..\LLVM-19.1.6\bin\clang.exe -Wno-deprecated-declarations -O3 main.c src/add_scalar.c src/fe.c src/ge.c src/key_exchange.c src/keypair.c src/sc.c src/seed.c src/sha512.c src/sign.c src/verify.c -o ed25519.exe -ladvapi32
..\LLVM-19.1.6\bin\clang.exe -shared -o ed25519.dll src/add_scalar.c src/fe.c src/ge.c src/key_exchange.c src/keypair.c src/sc.c src/seed.c src/sha512.c src/sign.c src/verify.c -ladvapi32 -Wl,/def:ed25519.def
..\LLVM-19.1.6\bin\clang.exe -Wno-deprecated-declarations -O3 main.c -o ed25519.exe -led25519
timeout /t 5
