package main

import (
	"os"
	"fmt"
	"strings"
	"os/exec"
	"io/ioutil"
	"path/filepath"
	"bufio"
	"regexp"
	"strconv"
	"time"
	"runtime"
)

var xmlData string = `<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup Label="ProjectConfigurations">
    <ProjectConfiguration Include="Debug|Win32">
      <Configuration>Debug</Configuration>
      <Platform>Win32</Platform>
    </ProjectConfiguration>
    <ProjectConfiguration Include="Release|Win32">
      <Configuration>Release</Configuration>
      <Platform>Win32</Platform>
    </ProjectConfiguration>
    <ProjectConfiguration Include="Debug|x64">
      <Configuration>Debug</Configuration>
      <Platform>x64</Platform>
    </ProjectConfiguration>
    <ProjectConfiguration Include="Release|x64">
      <Configuration>Release</Configuration>
      <Platform>x64</Platform>
    </ProjectConfiguration>
  </ItemGroup>
  <PropertyGroup Label="Globals">
    <VCProjectVersion>15.0</VCProjectVersion>
    <ProjectGuid>{F89B8BBB-D049-4053-B3E5-87377745086A}</ProjectGuid>
    <Keyword>Win32Proj</Keyword>
    <RootNamespace>dummyDLL</RootNamespace>
    <WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.Default.props" />
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Debug|Win32'" Label="Configuration">
    <ConfigurationType>DynamicLibrary</ConfigurationType>
    <UseDebugLibraries>true</UseDebugLibraries>
    <PlatformToolset>v142</PlatformToolset>
    <CharacterSet>Unicode</CharacterSet>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|Win32'" Label="Configuration">
    <ConfigurationType>DynamicLibrary</ConfigurationType>
    <UseDebugLibraries>false</UseDebugLibraries>
    <PlatformToolset>v142</PlatformToolset>
    <WholeProgramOptimization>true</WholeProgramOptimization>
    <CharacterSet>Unicode</CharacterSet>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Debug|x64'" Label="Configuration">
    <ConfigurationType>DynamicLibrary</ConfigurationType>
    <UseDebugLibraries>true</UseDebugLibraries>
    <PlatformToolset>v142</PlatformToolset>
    <CharacterSet>Unicode</CharacterSet>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'" Label="Configuration">
    <ConfigurationType>DynamicLibrary</ConfigurationType>
    <UseDebugLibraries>false</UseDebugLibraries>
    <PlatformToolset>v142</PlatformToolset>
    <WholeProgramOptimization>false</WholeProgramOptimization>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.props" />
  <ImportGroup Label="ExtensionSettings">
  </ImportGroup>
  <ImportGroup Label="Shared">
  </ImportGroup>
  <ImportGroup Label="PropertySheets" Condition="'$(Configuration)|$(Platform)'=='Debug|Win32'">
    <Import Project="$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props" Condition="exists('$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props')" Label="LocalAppDataPlatform" />
  </ImportGroup>
  <ImportGroup Label="PropertySheets" Condition="'$(Configuration)|$(Platform)'=='Release|Win32'">
    <Import Project="$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props" Condition="exists('$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props')" Label="LocalAppDataPlatform" />
  </ImportGroup>
  <ImportGroup Label="PropertySheets" Condition="'$(Configuration)|$(Platform)'=='Debug|x64'">
    <Import Project="$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props" Condition="exists('$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props')" Label="LocalAppDataPlatform" />
  </ImportGroup>
  <ImportGroup Label="PropertySheets" Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
    <Import Project="$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props" Condition="exists('$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props')" Label="LocalAppDataPlatform" />
  </ImportGroup>
  <PropertyGroup Label="UserMacros" />
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Debug|Win32'">
    <LinkIncremental>true</LinkIncremental>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Debug|x64'">
    <LinkIncremental>true</LinkIncremental>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|Win32'">
    <LinkIncremental>false</LinkIncremental>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
    <LinkIncremental>false</LinkIncremental>
    <EmbedManifest>false</EmbedManifest>
    <GenerateManifest>false</GenerateManifest>
    <TargetName>out</TargetName>
  </PropertyGroup>
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Debug|Win32'">
    <ClCompile>
      <PrecompiledHeader>NotUsing</PrecompiledHeader>
      <WarningLevel>Level3</WarningLevel>
      <Optimization>Disabled</Optimization>
      <SDLCheck>true</SDLCheck>
      <PreprocessorDefinitions>WIN32;_DEBUG;DUMMYDLL_EXPORTS;_WINDOWS;_USRDLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <ConformanceMode>true</ConformanceMode>
    </ClCompile>
    <Link>
      <SubSystem>Windows</SubSystem>
      <GenerateDebugInformation>true</GenerateDebugInformation>
	  <NoEntryPoint>true</NoEntryPoint>
    </Link>
  </ItemDefinitionGroup>
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Debug|x64'">
    <ClCompile>
      <PrecompiledHeader>NotUsing</PrecompiledHeader>
      <WarningLevel>Level3</WarningLevel>
      <Optimization>Disabled</Optimization>
      <SDLCheck>true</SDLCheck>
      <PreprocessorDefinitions>_DEBUG;DUMMYDLL_EXPORTS;_WINDOWS;_USRDLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <ConformanceMode>true</ConformanceMode>
    </ClCompile>
    <Link>
      <SubSystem>Windows</SubSystem>
      <GenerateDebugInformation>true</GenerateDebugInformation>
	  <NoEntryPoint>true</NoEntryPoint>
    </Link>
  </ItemDefinitionGroup>
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|Win32'">
    <ClCompile>
      <PrecompiledHeader>NotUsing</PrecompiledHeader>
      <WarningLevel>Level3</WarningLevel>
      <Optimization>MaxSpeed</Optimization>
      <FunctionLevelLinking>true</FunctionLevelLinking>
      <IntrinsicFunctions>true</IntrinsicFunctions>
      <SDLCheck>true</SDLCheck>
      <PreprocessorDefinitions>WIN32;NDEBUG;DUMMYDLL_EXPORTS;_WINDOWS;_USRDLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <ConformanceMode>true</ConformanceMode>
    </ClCompile>
    <Link>
      <SubSystem>Windows</SubSystem>
      <EnableCOMDATFolding>true</EnableCOMDATFolding>
      <OptimizeReferences>true</OptimizeReferences>
      <GenerateDebugInformation>true</GenerateDebugInformation>
	  <NoEntryPoint>true</NoEntryPoint>
    </Link>
  </ItemDefinitionGroup>
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
    <ClCompile>
      <PrecompiledHeader>NotUsing</PrecompiledHeader>
      <WarningLevel>Level3</WarningLevel>
      <Optimization>MinSpace</Optimization>
      <FunctionLevelLinking>true</FunctionLevelLinking>
      <IntrinsicFunctions>false</IntrinsicFunctions>
      <SDLCheck>true</SDLCheck>
      <PreprocessorDefinitions>NDEBUG;DUMMYDLL_EXPORTS;_WINDOWS;_USRDLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <ConformanceMode>true</ConformanceMode>
      <FavorSizeOrSpeed>Size</FavorSizeOrSpeed>
      <OmitFramePointers>true</OmitFramePointers>
      <WholeProgramOptimization>false</WholeProgramOptimization>
      <DisableLanguageExtensions>false</DisableLanguageExtensions>
      <OmitDefaultLibName>false</OmitDefaultLibName>
    </ClCompile>
    <Link>
      <SubSystem>Windows</SubSystem>
      <EnableCOMDATFolding>true</EnableCOMDATFolding>
      <OptimizeReferences>true</OptimizeReferences>
      <GenerateDebugInformation>false</GenerateDebugInformation>
      <LinkErrorReporting>NoErrorReport</LinkErrorReporting>
      <ImageHasSafeExceptionHandlers>false</ImageHasSafeExceptionHandlers>
      <AdditionalDependencies>kernel32.lib;user32.lib;gdi32.lib;winspool.lib;comdlg32.lib;advapi32.lib;shell32.lib;ole32.lib;oleaut32.lib;uuid.lib;odbc32.lib;odbccp32.lib;%(AdditionalDependencies)</AdditionalDependencies>
      <LargeAddressAware>
      </LargeAddressAware>
      <CLRUnmanagedCodeCheck>
      </CLRUnmanagedCodeCheck>
      <CLRSupportLastError>
      </CLRSupportLastError>
      <ForceSymbolReferences>
      </ForceSymbolReferences>
      <ForceFileOutput>
      </ForceFileOutput>
      <NoEntryPoint>true</NoEntryPoint>
    </Link>
    <Xdcmake>
      <DocumentLibraryDependencies>false</DocumentLibraryDependencies>
    </Xdcmake>
  </ItemDefinitionGroup>
  <ItemGroup>
    <ClInclude Include="stdafx.h" />
    <ClInclude Include="targetver.h" />
  </ItemGroup>
  <ItemGroup>
    <ClCompile Include="dllmain.cpp" />
  </ItemGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.targets" />
  <ImportGroup Label="ExtensionTargets">
  </ImportGroup>
</Project>
`

var defineData string = `
#define CFUNC(func, ...) __declspec(dllexport) void func(__VA_ARGS__) { return; }
#define CPPFUNC(...) __declspec(dllexport) __VA_ARGS__
`
var outData string = defineData

func RemoveDir(dir string) error {
    d, err := os.Open(dir)
    if err != nil {
        return err
    }
    defer d.Close()
	err = os.RemoveAll(dir)
	if err != nil {
		return err
	}
    return nil
}

func createFile(name string, data string) {
	f, _ := os.Create(name)
	defer f.Close()
	w := bufio.NewWriter(f)
	n4, _ := w.WriteString(data)
	if n4 == 0 {
		fmt.Println("Error: Please check if you have a permission to the temporary directory(1)")
		os.Exit(1)
	}
	w.Flush()
}

func checkStatName(name string) {
	if _, err := os.Stat(name); os.IsNotExist(err) {
		fmt.Println("Error: File not found - " + name)
		os.Exit(1)
	}
}

func errChk(err error) {
    if err != nil {
		fmt.Println(err)
		os.Exit(1)
    }
}

func main() {
	var PF86 string = os.Getenv("ProgramFiles(x86)")
	var PF string = os.Getenv("ProgramFiles")
	var tmpDir string = os.Getenv("TEMP") + "\\dummydll\\" + time.Now().Format("20060102150405")
	var origInstallPath string = ""
	var realPF string = ""
	var cmd string = ""
	var finalVer string = ""
	var newStr string = ""
	var homeDir string = ""
	var isSystemX86 bool = false
	var isDllX86 bool = false
	var cArray []string
	var cppArray []string

	if runtime.GOOS != "windows" {
		fmt.Println("This program requires Microsoft Windows")
		os.Exit(1)
	}

	homeDir, err := os.Getwd(); errChk(err)

	if !(len(os.Args) == 2) {
		fmt.Println("Dummy DLL Generator v0.1 (20190625a)\n")
		fmt.Println("Usage: " + filepath.Base(os.Args[0]) + " [DLL path]")
		os.Exit(1)
	}

	checkStatName(os.Args[1])
	if !(strings.Compare(PF86, "") == 0) {
		realPF = PF86
	} else if !(strings.Compare(PF, "") == 0) {
		realPF = PF
		isSystemX86 = true
	} else {
		fmt.Println("Error: ProgramFiles environment is not set")
		os.Exit(1)
	}

	cmd = realPF + "\\Microsoft Visual Studio\\Installer\\vswhere.exe"
	if _, err := os.Stat(cmd); os.IsNotExist(err) {
		fmt.Println("Error: Visual Studio 15.2 (26418.1 Preview) or higher must be installed")
		os.Exit(1)
	}

	cmdLine := exec.Command(cmd, "-latest", "-property", "installationPath")
	cmdOut, _ := cmdLine.StdoutPipe()
	err = cmdLine.Start()
	if err != nil {
		fmt.Println("Error: Could not run vswhere")
		os.Exit(1)
	}
	cmdBytes, _ := ioutil.ReadAll(cmdOut)
	newStr = strings.TrimSpace(string(cmdBytes))
	origInstallPath = newStr
	newStr += "\\VC\\Tools\\MSVC"

	fileInfo, err := ioutil.ReadDir(newStr)
    if err != nil {
		fmt.Println("Error: Could not run vswhere")
		os.Exit(1)
    }
    for _, file := range fileInfo {
		if info, err := os.Stat(newStr + "\\" + file.Name()); err == nil && info.IsDir() {
			finalVer = file.Name()
        }
    }
	newStr = newStr + "\\" + finalVer + "\\bin"
	if isSystemX86 {
		newStr += "\\Hostx86"
	} else {
		newStr += "\\Hostx64"
	}
	cmd = newStr + "\\x86\\dumpbin.exe"
	checkStatName(cmd)
	cmdLine = exec.Command(cmd, "/EXPORTS", "/HEADERS", os.Args[1])
	cmdOut, _ = cmdLine.StdoutPipe()
	err = cmdLine.Start()
	if err != nil {
		fmt.Println("Error: Could not run " + cmd)
		os.Exit(1)
	}
	cmdBytes, _ = ioutil.ReadAll(cmdOut)

	scanner := bufio.NewScanner(strings.NewReader(strings.TrimSpace(string(cmdBytes))))
	level := 0
	for scanner.Scan() {
		matched, _ := regexp.MatchString("^FILE HEADER VALUES", scanner.Text())
		if matched {
			level = 1
			continue
		}
		if level == 1 {
			matched, _ := regexp.MatchString(` machine \(`, scanner.Text())
			if matched {
				matched, _ := regexp.MatchString(` \(x86\)`, scanner.Text())
				if matched {
					isDllX86 = true
				}
				continue
			}
			matched, _ = regexp.MatchString(`^\s*ordinal\s*hint\s*RVA\s*name\s*$`, scanner.Text())
			if matched {
				level = 2
				continue
			}
		}
		if level == 2 {
			matched, _ = regexp.MatchString(`^\s*Summary\s*$`, scanner.Text())
			if matched {
				break
			}
			newLn := strings.TrimSpace(scanner.Text())
			re := regexp.MustCompile(`\s+`)
			if len(re.Split(newLn, -1)) == 4 {
				newLn2 := re.Split(newLn, -1)[3]
				matched, _ = regexp.MatchString(`(^\?|@)`, newLn2)
				if matched {
					cmd = newStr + "\\x86\\undname.exe"
					cmdLine := exec.Command(cmd, newLn2)
					cmdOut, _ := cmdLine.StdoutPipe()
					err := cmdLine.Start()
					if err != nil {
						fmt.Println("Error: Could not run undname")
						os.Exit(1)
					}
					cmdBytes2, _ := ioutil.ReadAll(cmdOut)
					re = regexp.MustCompile(`(?s).*is :- `)
					cmdByte3 := re.ReplaceAllString(strings.TrimSpace(string(cmdBytes2)), "")
					var newCmdByte3 string = "";
					for num, sstr := range strings.Split(cmdByte3, ",") {
						num++
						matched, _ = regexp.MatchString(`\)"$`, sstr)
						if matched {
							sstr = strings.Replace(sstr, `)"`, "", -1)
							newCmdByte3 = newCmdByte3 + sstr + " data" + strconv.FormatInt(int64(num), 10) + ")"
						} else {
							newCmdByte3 = newCmdByte3 + sstr + " data" + strconv.FormatInt(int64(num), 10) + ","
						}
					}
					cppArray = append(cppArray, strings.Replace(newCmdByte3, `"`, "", -1))
				} else {
					cArray = append(cArray, newLn2)
				}
			}
		}
	}

	fmt.Println("DLL Name: " + os.Args[1])
	if isDllX86 {
		fmt.Println("DLL Bit: x86")
	} else {
		fmt.Println("DLL Bit: x64")
	}
	
	// cArray
	outData += `extern "C" {` + "\n"
	for _, sstr := range cArray {
		outData += "\tCFUNC(" + sstr + ", void)\n"
	}
	outData += `}` + "\n\n"

	// cppArray
	for _, sstr := range cppArray {
		re := regexp.MustCompile(`^(\S+ \*|\S+)\s.*`)
		var dataType string = re.ReplaceAllString(sstr, "$1")
		if dataType == "void" {
			outData += "CPPFUNC(" + sstr + " { return; })\n"
		} else {
			outData += "CPPFUNC(" + sstr + " { return (" + dataType + ")0; })\n"
		}
	}
	os.MkdirAll(tmpDir, os.ModePerm)
	createFile(tmpDir + "\\dllmain.cpp", outData)
	createFile(tmpDir + "\\dllmain.xml", xmlData)
	fmt.Println(tmpDir)

	if isDllX86 {
		cmd = origInstallPath + "\\MSBuild\\Current\\Bin\\MSBuild.exe"
	} else {
		cmd = origInstallPath + "\\MSBuild\\Current\\Bin\\amd64\\MSBuild.exe"
	}
	checkStatName(cmd)
	if isDllX86 {
		fmt.Println(cmd + " " + tmpDir + "\\dllmain.xml", "/property:Configuration=Release;Platform=x86;OutDir=" + homeDir)
		cmdLine = exec.Command(cmd, tmpDir + "\\dllmain.xml", "/property:Configuration=Release;Platform=x86;OutDir=" + homeDir)
	} else {
		fmt.Println(cmd + " " + tmpDir + "\\dllmain.xml", "/property:Configuration=Release;Platform=x64;OutDir=" + homeDir)
		cmdLine = exec.Command(cmd, tmpDir + "\\dllmain.xml", "/property:Configuration=Release;Platform=x64;OutDir=" + homeDir)
	}
	cmdOut, _ = cmdLine.StdoutPipe()
	err = cmdLine.Start()
	if err != nil {
		fmt.Println("Error: Could not run msbuild")
		os.Exit(1)
	}
	cmdBytes, _ = ioutil.ReadAll(cmdOut)
	newStr = strings.TrimSpace(string(cmdBytes))
	fmt.Println(newStr)

	RemoveDir(tmpDir)
}
