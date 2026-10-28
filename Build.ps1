param([string]$VdeviceSetup,[string]$EngineCab,[string]$EngineManifest,[switch]$TestsOnly,[switch]$Asan,[string]$ToolsetVersion)
$ErrorActionPreference='Stop'
$project=$PSScriptRoot
$build=Join-Path $project $(if($Asan){'obj\AsanDirect'}else{'obj\BuildDirect'})
if(!(Test-Path -LiteralPath (Join-Path $project 'obj\Upstream\MoonlightCommon\CMakeLists.txt'))){throw 'First run: python Tools/Prepare-Moonlight.py'}
$configure=@('-S',$project,'-B',$build,'-G','Visual Studio 17 2022','-A','x64',('-DRDC_ASAN='+$(if($Asan){'ON'}else{'OFF'})))
foreach($entry in @(@('VDEVICE_SETUP_FILE',$VdeviceSetup),@('RDC_ENGINE_CAB',$EngineCab),@('RDC_ENGINE_MANIFEST',$EngineManifest))){$value=$entry[1];if($value){$value=[IO.Path]::GetFullPath($value);if(!(Test-Path -LiteralPath $value)){throw "Missing payload: $value"}};$configure+=('-D'+$entry[0]+'='+$value)}
& cmake @configure
if($LASTEXITCODE){throw 'CMake configuration failed'}
$buildArgs=@('--build',$build,'--config','Release','--parallel','3')
if($TestsOnly){$buildArgs+=@('--target','CoreTests','InputTests','DiscoveryTests','SetupTests','GameStreamTests','GameStreamCodecTests','EngineBundleTests')}
if($ToolsetVersion){$buildArgs+=@('--',('/p:VCToolsVersion='+$ToolsetVersion))}
& cmake @buildArgs
if($LASTEXITCODE){throw 'C++ compilation failed'}
& ctest --test-dir $build -C Release --output-on-failure
if($LASTEXITCODE){throw 'Offline tests failed'}
Write-Host 'Built and tested. No installation, desktop capture or input injection was performed.'
