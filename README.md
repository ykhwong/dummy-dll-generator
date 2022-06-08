# Dummy DLL Generator

## About
The Dummy DLL Generator generates a dummy DLL file by analyzing a DLL file. The DLL stands for Dynamic-link library, as implemented in Microsoft Windows.
This tool can handle both C and C++ convention symbols.

## Getting started
### Prerequisites
* Version v0.2 : Visual Studio 2017 15.2 (26418.1 Preview) or higher
* Version v0.1 (20220205a) : Visual Studio 2022 only
* Version v0.1 (20190627a) : Visual Studio 2017 and 2019 only

### Command Line Options

```sh
   dummyDLL.exe [DLL path]
```

## Technical details
The Dummy DLL Generator identifies the following information after importing a DLL file:
* Current system bit and the latest version information of MSVC instance
* Machine bit from the file header
* C/C++ symbols from the file export, including C++ mangled functions

After analyzing the DLL file, the Dummy DLL Generator produces out.dll in the working directory, using the MSBuild. The output library provides no entry point.

![Dummy DLL Generator Screenshot 1](https://raw.githubusercontent.com/ykhwong/dummy-dll-generator/master/resources/dummyDLL_sshot.png)
