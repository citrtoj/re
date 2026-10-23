Laboratory 2 - PE samples
=========================

These files are only meant to be READ by your parser. Do not run them.

valid/        Normal PE files built from the sources in source/
              console32.exe   32-bit console program (PE32)
              console64.exe   64-bit console program (PE32+)
              mathlib32.dll   32-bit DLL with exports
              mathlib64.dll   64-bit DLL with exports
              tls64.exe       64-bit program with a TLS callback (bonus task)

malformed/    Files broken (or made suspicious) on purpose. Your parser must
              never crash on them. Find out what is wrong with each one.

expected/     The output of the reference parser for every file above
              (<file name>.txt). For broken files the exact error text does
              not matter, only that you stop with an error at the same step.

source/       C sources of the valid samples (built with clang + MSVC linker).
