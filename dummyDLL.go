package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var xmlData = `<?xml version="1.0" encoding="utf-8"?>
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
    <PlatformToolset>v143</PlatformToolset>
    <CharacterSet>Unicode</CharacterSet>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|Win32'" Label="Configuration">
    <ConfigurationType>DynamicLibrary</ConfigurationType>
    <UseDebugLibraries>false</UseDebugLibraries>
    <PlatformToolset>v143</PlatformToolset>
    <WholeProgramOptimization>true</WholeProgramOptimization>
    <CharacterSet>Unicode</CharacterSet>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Debug|x64'" Label="Configuration">
    <ConfigurationType>DynamicLibrary</ConfigurationType>
    <UseDebugLibraries>true</UseDebugLibraries>
    <PlatformToolset>v143</PlatformToolset>
    <CharacterSet>Unicode</CharacterSet>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'" Label="Configuration">
    <ConfigurationType>DynamicLibrary</ConfigurationType>
    <UseDebugLibraries>false</UseDebugLibraries>
    <PlatformToolset>v143</PlatformToolset>
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
      <GenerateDebugInformation>false</GenerateDebugInformation>
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
      <GenerateDebugInformation>false</GenerateDebugInformation>
	  <NoEntryPoint>true</NoEntryPoint>
    </Link>
  </ItemDefinitionGroup>
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|Win32'">
    <ClCompile>
      <PrecompiledHeader>NotUsing</PrecompiledHeader>
      <WarningLevel>Level3</WarningLevel>
      <Optimization>MinSpace</Optimization>
      <FunctionLevelLinking>true</FunctionLevelLinking>
      <IntrinsicFunctions>false</IntrinsicFunctions>
      <SDLCheck>true</SDLCheck>
      <PreprocessorDefinitions>WIN32;NDEBUG;DUMMYDLL_EXPORTS;_WINDOWS;_USRDLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <ConformanceMode>true</ConformanceMode>
    </ClCompile>
    <Link>
      <SubSystem>Windows</SubSystem>
      <EnableCOMDATFolding>true</EnableCOMDATFolding>
      <OptimizeReferences>true</OptimizeReferences>
      <GenerateDebugInformation>false</GenerateDebugInformation>
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
    <ClCompile Include="out.cpp" />
  </ItemGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.targets" />
  <ImportGroup Label="ExtensionTargets">
  </ImportGroup>
</Project>
`

const verInfo string = "v0.2 (20220608a)"
const defineData string = `
#define CFUNC(func, ...) __declspec(dllexport) void func(__VA_ARGS__) { return; }
#define CPPFUNC(...) __declspec(dllexport) __VA_ARGS__
`

var outData = defineData

func removeDir(dir string) error {
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
		exitWithMsg("Error: Please check if you have a permission to the temporary directory", 1)
	}
	w.Flush()
}

func checkStatName(name string) {
	if _, err := os.Stat(name); os.IsNotExist(err) {
		exitWithMsg("Error: File not found - "+name, 1)
	}
}

func errChk(err error) {
	if err != nil {
		exitWithMsg(err.Error(), 1)
	}
}

func SliceUniqMap(s []string) []string {
	seen := make(map[string]struct{}, len(s))
	j := 0
	for _, v := range s {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		s[j] = v
		j++
	}
	return s[:j]
}

func exitWithMsg(msg string, code int) {
	fmt.Println(msg)
	os.Exit(code)
}

func main() {
	var PF86 = os.Getenv("ProgramFiles(x86)")
	var PF = os.Getenv("ProgramFiles")
	var tmpDir = os.Getenv("TEMP") + `\dummydll\` + time.Now().Format("20060102150405")
	var origInstallPath = ""
	var realPF = ""
	var cmd = ""
	var finalVer = ""
	var finalMscVer = ""
	var finalPlatformVer = ""
	var finalPlatformToolsetDir = ""
	var newStr = ""
	var homeDir = ""
	var isSystemX86 = false
	var isDllX86 = false
	var cArray []string
	var cppArray []string
	var cppStructCases []string

	if runtime.GOOS != "windows" {
		exitWithMsg("This program requires Microsoft Windows", 1)
	}

	homeDir, err := os.Getwd()
	errChk(err)

	fmt.Println("\nDummy DLL Generator " + verInfo)
	fmt.Println("========================================================================================")
	if !(len(os.Args) == 2) {
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
		exitWithMsg("Error: ProgramFiles environment is not set", 1)
	}

	// Look for vswhere
	cmd = realPF + "\\Microsoft Visual Studio\\Installer\\vswhere.exe"
	if _, err := os.Stat(cmd); os.IsNotExist(err) {
		exitWithMsg("Error: Visual Studio 15.2 (26418.1 Preview) or higher must be installed", 1)
	}

	// Look for the latest stable version of MSVC
	cmdLine := exec.Command(cmd, "-latest", "-property", "installationPath")
	cmdOut, _ := cmdLine.StdoutPipe()
	err = cmdLine.Start()
	if err != nil {
		exitWithMsg("Error: Could not run vswhere", 1)
	}
	cmdBytes, _ := ioutil.ReadAll(cmdOut)
	newStr = strings.TrimSpace(string(cmdBytes))
	origInstallPath = newStr
	newStr += "\\VC\\Tools\\MSVC"

	fileInfo, err := ioutil.ReadDir(newStr)

	// Look for the latest prerelease version of MSVC
	if err != nil {
		cmdLine = exec.Command(cmd, "-prerelease", "-property", "installationPath")
		cmdOut, _ = cmdLine.StdoutPipe()
		err = cmdLine.Start()
		if err != nil {
			exitWithMsg("Error: Could not run vswhere", 1)
		}
		cmdBytes, _ = ioutil.ReadAll(cmdOut)
		newStr = strings.TrimSpace(string(cmdBytes))
		origInstallPath = newStr
		newStr += "\\VC\\Tools\\MSVC"

		fileInfo, err = ioutil.ReadDir(newStr)
		if err != nil {
			exitWithMsg("Error: Could not read directory: "+newStr, 1)
		}

	}
	for _, file := range fileInfo {
		if info, err := os.Stat(newStr + "\\" + file.Name()); err == nil && info.IsDir() {
			finalVer = file.Name()
		}
	}

	// Run dumpbin to get the EXPORTS and HEADERS
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
		exitWithMsg("Error: Could not run "+cmd, 1)
	}

	// Look for the latest MSVC version
	fileInfo, err = ioutil.ReadDir(origInstallPath + "\\MSBuild\\Microsoft\\VC")
	if err != nil {
		exitWithMsg("Error: Could not read directory: "+origInstallPath+"\\MSBuild\\Microsoft\\VC", 1)
	}
	for _, fileInfo := range fileInfo {
		if fileInfo.IsDir() {
			finalMscVer = fileInfo.Name()
		}
	}

	// Scan the output of dumpbin
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
			matched, _ = regexp.MatchString(`^\s*(Summary|SECTION HEADER.*)\s*$`, scanner.Text())
			if matched {
				break
			}
			newLn := strings.TrimSpace(scanner.Text())
			re := regexp.MustCompile(`\s+`)
			if len(re.Split(newLn, -1)) == 4 {
				newLn2 := re.Split(newLn, -1)[3]
				matched, _ = regexp.MatchString(`(^\?|@)`, newLn2)

				if matched {
					// C++ symbols
					var newCmdByte3 = ""
					cmd = newStr + `\x86\undname.exe`
					cmdLine := exec.Command(cmd, newLn2)
					cmdOut, _ := cmdLine.StdoutPipe()
					err := cmdLine.Start()
					if err != nil {
						exitWithMsg("Error: Could not run undname", 1)
					}
					cmdBytes2, _ := ioutil.ReadAll(cmdOut)
					re = regexp.MustCompile(`(?s).*is :- `)
					cmdByte3 := re.ReplaceAllString(strings.TrimSpace(string(cmdBytes2)), "")

					re = regexp.MustCompile(`(\(|,)(struct) (\S+)`)
					matches := re.FindAllStringSubmatch(cmdByte3, -1)
					for _, v := range matches {
						var v2 = v[2]
						var v3 = v[3]
						re = regexp.MustCompile(`(,|\)).*`)
						v3 = re.ReplaceAllString(v3, "")
						if v2 == "struct" {
							cppStructCases = append(cppStructCases, v3)
						}
					}

					for num, sstr := range regexp.MustCompile(`,`).Split(cmdByte3, -1) {
						num++
						matched, _ = regexp.MatchString(`\)"$`, sstr)
						if matched {
							re = regexp.MustCompile(`\)\)"$`)
							matched, _ = regexp.MatchString(`\)`, sstr)
							if matched {
								newCmdByte3 = newCmdByte3 + sstr
							} else {
								sstr = strings.Replace(sstr, `)"`, "", -1)
								newCmdByte3 = newCmdByte3 + sstr + " data" + strconv.FormatInt(int64(num), 10) + ")"
								newCmdByte3 += `"`
							}
						} else {
							matched, _ = regexp.MatchString(`\)$`, sstr)
							if matched {
								re = regexp.MustCompile(`\)\s*$`)
								sstr = re.ReplaceAllString(sstr, "")
								newCmdByte3 = newCmdByte3 + sstr + " data" + strconv.FormatInt(int64(num), 10) + "),"
							} else {
								newCmdByte3 = newCmdByte3 + sstr + " data" + strconv.FormatInt(int64(num), 10) + ","
							}
						}
					}
					cppArray = append(cppArray, strings.Replace(newCmdByte3, `"`, "", -1))
				} else {
					// C symbols
					cArray = append(cArray, newLn2)
				}
			}
		}
	}

	cppStructCases = SliceUniqMap(cppStructCases)
	for _, sstr := range cppStructCases {
		outData += "typedef struct " + sstr + " {} " + sstr + ";\n"
	}

	// Get the latest version of PlatformToolSets
	if isDllX86 {
		finalPlatformToolsetDir = origInstallPath + "\\MSBuild\\Microsoft\\VC\\" + finalMscVer + "\\Platforms\\Win32\\PlatformToolsets"
	} else {
		finalPlatformToolsetDir = origInstallPath + "\\MSBuild\\Microsoft\\VC\\" + finalMscVer + "\\Platforms\\x64\\PlatformToolsets"
	}
	fileInfo, err = ioutil.ReadDir(finalPlatformToolsetDir)
	if err != nil {
		exitWithMsg("Error: Could not read directory: "+finalPlatformToolsetDir, 1)
	}
	for _, fileInfo := range fileInfo {
		if fileInfo.IsDir() {
			finalPlatformVer = fileInfo.Name()
		}
	}

	// Display the number of symbols
	fmt.Println("Input DLL: " + os.Args[1])
	fmt.Println("Output DLL: out.dll")
	fmt.Printf("No. of symbols: C (" + strconv.FormatInt(int64(len(cArray)), 10) + "),")
	fmt.Println(" C++ (" + strconv.FormatInt(int64(len(cppArray)), 10) + ")")
	if isDllX86 {
		fmt.Println("DLL Bit: x86")
	} else {
		fmt.Println("DLL Bit: x64")
	}
	fmt.Println("\nBuilding...")

	// Create cArray
	outData += `extern "C" {` + "\n"
	for _, sstr := range cArray {
		outData += "\tCFUNC(" + sstr + ", void)\n"
	}
	outData += `}` + "\n\n"

	// Create cppArray
	for _, sstr := range cppArray {
		re := regexp.MustCompile(`^(\S+ \*|\S+)\s.*`)
		var dataType = re.ReplaceAllString(sstr, "$1")
		if dataType == "void" {
			outData += "CPPFUNC(" + sstr + " { return; })\n"
		} else {
			outData += "CPPFUNC(" + sstr + " { return (" + dataType + ")0; })\n"
		}
	}
	os.MkdirAll(tmpDir, os.ModePerm)
	createFile(tmpDir+"\\out.cpp", outData)
	createFile(tmpDir+"\\out.xml", xmlData)

	if isDllX86 {
		cmd = origInstallPath + "\\MSBuild\\Current\\Bin\\MSBuild.exe"
	} else {
		cmd = origInstallPath + "\\MSBuild\\Current\\Bin\\amd64\\MSBuild.exe"
	}
	checkStatName(cmd)

	platform := "Platform="
	if isDllX86 {
		platform += "x86"
	} else {
		platform += "x64"
	}

	// Run MSBuild to create a dummy dll
	cmdLine = exec.Command(cmd, tmpDir+"\\out.xml",
		"/p:PlatformToolset="+finalPlatformVer,
		"/property:Configuration=Release;"+platform+";OutDir="+homeDir+"\\",
		"/clp:NoSummary;NoItemAndPropertyList;ErrorsOnly", "/verbosity:quiet", "/nologo")
	cmdOut, _ = cmdLine.StdoutPipe()
	err = cmdLine.Start()
	if err != nil {
		exitWithMsg("Error: Could not run MSBuild", 1)
	}
	cmdBytes, _ = ioutil.ReadAll(cmdOut)
	newStr = strings.TrimSpace(string(cmdBytes))
	if newStr == "" {
		fmt.Println("Done")
	} else {
		fmt.Println(newStr)
	}

	removeDir(tmpDir)
}
