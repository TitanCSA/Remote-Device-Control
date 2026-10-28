param([string]$VdeviceSetup,[switch]$TestsOnly,[switch]$Asan)
$ErrorActionPreference='Stop'
$project=$PSScriptRoot
$build=Join-Path $project $(if($Asan){'obj\Asan'}else{'obj\Build'})
if(!$VdeviceSetup){$VdeviceSetup=Join-Path $project 'obj\Payload\VdeviceSetupConsole.exe'}
$args=@('-S',$project,'-B',$build,'-G','Visual Studio 17 2022','-A','x64',('-DRDC_ASAN='+$(if($Asan){'ON'}else{'OFF'})))
$hasPayload=Test-Path -LiteralPath $VdeviceSetup
$args+=('-DVDEVICE_SETUP_FILE='+$(if($hasPayload){[IO.Path]::GetFullPath($VdeviceSetup)}else{''}))
& cmake @args
if($LASTEXITCODE){throw 'CMake configuration failed'}
$buildArgs=@('--build',$build,'--config','Release','--parallel','2')
if($TestsOnly){$buildArgs+=@('--target','CoreTests','InputTests','CaptureTests');if($hasPayload){$buildArgs+='SetupTests'}}
& cmake @buildArgs
if($LASTEXITCODE){throw 'C++ compilation failed'}
& ctest --test-dir $build -C Release --output-on-failure
if($LASTEXITCODE){throw 'Offline tests failed'}
Write-Host 'Built and tested. No installation, desktop capture or input injection was performed.'
