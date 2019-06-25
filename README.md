# Dummy DLL Generator

## INTRODUCTION
Based on the existing DLL file, dummy-dll-generator generates a dummy DLL file.
This tool can handle both C and C++ convention symbols.

## Getting started
### Prerequisites
* Visual Studio 15.2 (26418.1 Preview) or higher

### Command Line Options

```sh
   dummyDLL.exe [DLL path]
```

## Technical details
dummy-dll-generator identifies the following information after importing the existing DLL file.
* Current system bit and the latest version information of MSVC instance
* Which machine bit is used (e.g, x86 or x64) by taking the file header
* Both C++ mangled functions and symbols, and C symbols exported in the DLL

After analyzing the DLL, the dummy-dll-generator produces the out.dll in the working directory by using the MSBuild.
No entry point is specified for the compilation.

![Dummy DLL Generator Screenshot 1](https://raw.githubusercontent.com/ykhwong/dummy-dll-generator/master/resources/dummyDLL_sshot.png)
