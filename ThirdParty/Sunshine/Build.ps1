param([string]$WorkDirectory,[string]$MsysDirectory='C:\msys64',[string]$Python='python.exe',[string]$SourceDirectory,[int]$Jobs=3)
$ErrorActionPreference='Stop'
$project=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
if(!$WorkDirectory){$WorkDirectory=Join-Path $project 'obj'}
$work=[IO.Path]::GetFullPath($WorkDirectory)
$deps=Join-Path $work 'ThirdParty\SunshineDeps'
$prefix=Join-Path $deps 'root\ucrt64'
$source=if($SourceDirectory){[IO.Path]::GetFullPath($SourceDirectory)}else{Join-Path $work 'Upstream\Sunshine'}
$build=Join-Path $work 'SunshineBuild'
$stage=Join-Path $work 'Payload\Engine'
function Run([string]$Program,[string[]]$Arguments){& $Program @Arguments;if($LASTEXITCODE){throw "$Program failed with exit code $LASTEXITCODE"}}
function Fetch([string]$Url,[string]$Path,[string]$Hash){
 if((Test-Path -LiteralPath $Path) -and (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -eq $Hash){return}
 Run "$env:WINDIR\System32\curl.exe" @('--fail','--location','--silent','--show-error','--retry','2','--connect-timeout','15','--max-time','180','--output',$Path,$Url)
 if((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne $Hash){throw "SHA256 mismatch: $Path"}
}
if(!(Test-Path -LiteralPath (Join-Path $MsysDirectory 'usr\bin\sh.exe'))){throw 'MSYS2 base tools are required; pass -MsysDirectory. No packages are installed globally by this script.'}
New-Item -ItemType Directory -Path "$deps\archives","$deps\root","$deps\installed",$build,"$stage\assets" -Force | Out-Null
foreach($package in (Get-Content -LiteralPath "$PSScriptRoot\MsysPackages.json" -Raw | ConvertFrom-Json)){
 if($package.File -notmatch '^mingw-w64-ucrt-x86_64-[A-Za-z0-9+_.~=\-]+\.pkg\.tar\.zst$'){throw 'Unexpected package name'}
 $archive=Join-Path "$deps\archives" $package.File
 Fetch $package.Url $archive $package.Sha256
 $stamp=Join-Path "$deps\installed" ($package.File+'.sha256')
 if((Test-Path -LiteralPath $stamp) -and (Get-Content -LiteralPath $stamp -Raw).Trim() -eq $package.Sha256){continue}
 $names=& "$env:WINDIR\System32\tar.exe" -tf $archive
 if($LASTEXITCODE){throw 'Cannot inspect package'}
 foreach($name in $names){if($name -match '^/|^[A-Za-z]:|(^|/)\.\.(/|$)'){throw 'Unsafe package path'}}
 Run "$env:WINDIR\System32\tar.exe" @('-xf',$archive,'-C',"$deps\root")
 [IO.File]::WriteAllText($stamp,$package.Sha256,[Text.UTF8Encoding]::new($false))
}
$env:PATH="$prefix\bin;$MsysDirectory\usr\bin;"+$env:PATH
$env:PKG_CONFIG_PATH="$prefix\lib\pkgconfig"
$env:CMAKE_PREFIX_PATH=$prefix
$snapshot=Test-Path -LiteralPath "$source\.rdc-source-pin"
if(!$snapshot -and !(Test-Path -LiteralPath "$source\.git")){
 New-Item -ItemType Directory -Path (Split-Path -Parent $source) -Force | Out-Null
 Run 'git.exe' @('clone','--filter=blob:none','--no-checkout','https://github.com/LizardByte/Sunshine.git',$source)
 Run 'git.exe' @('-C',$source,'fetch','--depth','1','origin','86188d47a7463b0f73b35de18a628353adeaa20e')
 Run 'git.exe' @('-C',$source,'checkout','--detach','FETCH_HEAD')
}
$pin=if($snapshot){(Get-Content -LiteralPath "$source\.rdc-source-pin" -Raw).Trim()}else{& git.exe -C $source rev-parse HEAD}
if($pin -ne '86188d47a7463b0f73b35de18a628353adeaa20e'){throw 'The existing build checkout has another revision; select an empty -WorkDirectory'}
$modules=@('third-party/build-deps','third-party/moonlight-common-c','third-party/libdisplaydevice','third-party/Simple-Web-Server','third-party/nanors','third-party/nv-codec-headers','third-party/nvapi-open-source-sdk','third-party/tray')
if(!$snapshot){Run 'git.exe' (@('-C',$source,'submodule','update','--init','--recursive','--depth','1','--jobs',"$Jobs",'--')+$modules)}
if($snapshot -and !(Test-Path -LiteralPath "$source\third-party\build-deps\dist\Windows-AMD64\lib\libavcodec.a")){
 # Source archives omit prepared binaries for all platforms. Fetch only the
 # exact Windows x64 artifact tree needed by upstream's link configuration.
 $prepared=Join-Path $work 'Upstream\CodecPrepared'
 if(!(Test-Path -LiteralPath "$prepared\.git")){
  New-Item -ItemType Directory -Path $prepared -Force | Out-Null
  Run 'git.exe' @('-C',$prepared,'init')
  Run 'git.exe' @('-C',$prepared,'remote','add','origin','https://github.com/LizardByte/build-deps.git')
  Run 'git.exe' @('-C',$prepared,'sparse-checkout','set','dist/Windows-AMD64')
  Run 'git.exe' @('-C',$prepared,'fetch','--depth','1','--filter=blob:none','origin','c38829d6b8c35b64b3ff7a569f51978ed72c4292')
  Run 'git.exe' @('-C',$prepared,'checkout','--detach','FETCH_HEAD')
 }
 if((& git.exe -C $prepared rev-parse HEAD) -ne 'c38829d6b8c35b64b3ff7a569f51978ed72c4292'){throw 'Unexpected prepared codec revision'}
 New-Item -ItemType Directory -Path "$source\third-party\build-deps\dist" -Force | Out-Null
 Copy-Item -LiteralPath "$prepared\dist\Windows-AMD64" -Destination "$source\third-party\build-deps\dist\Windows-AMD64" -Recurse -Force
}
$recipeFiles=@('Apply.py','InputQueue.inc','InputValidation.inc','RdcPairing.inc','Patches\upstream-certificate-validation.patch','Patches\upstream-enet-control-bounds.patch')
$recipe=($recipeFiles | ForEach-Object {$_+':'+(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $_) -Algorithm SHA256).Hash}) -join "`n"
$recipeStamp=Join-Path $source '.rdc-recipe-hashes'
if((Get-Content -LiteralPath "$source\src\platform\windows\input.cpp" -Raw) -notmatch 'RDC_VDEVICE_BACKEND'){
 Run $Python @("$PSScriptRoot\Apply.py",$source,$project)
 [IO.File]::WriteAllText($recipeStamp,$recipe,[Text.UTF8Encoding]::new($false))
}elseif(!$snapshot -and (!(Test-Path -LiteralPath $recipeStamp) -or (Get-Content -LiteralPath $recipeStamp -Raw) -ne $recipe)){
 throw 'The cached checkout was patched with another recipe. Select an empty -WorkDirectory; no edited source is discarded.'
}
$p=$prefix.Replace('\','/')
Push-Location $source
try{
 Run "$prefix\bin\cmake.exe" @('-S',$source,'-B',$build,'-G','Ninja',"-DCMAKE_C_COMPILER=$p/bin/gcc.exe","-DCMAKE_CXX_COMPILER=$p/bin/g++.exe","-DCMAKE_MAKE_PROGRAM=$p/bin/ninja.exe","-DCMAKE_PREFIX_PATH=$p","-DRDC_SOURCE_ROOT=$($project.Replace('\','/'))",'-DCMAKE_BUILD_TYPE=Release','-DBUILD_DOCS=OFF','-DBUILD_TESTS=OFF','-DSUNSHINE_ENABLE_TRAY=OFF','-DSUNSHINE_PUBLISHER_NAME=TitanCSA','-DSUNSHINE_PUBLISHER_ISSUE_URL=https://github.com/TitanCSA/Remote-Device-Control/issues')
 Run "$prefix\bin\cmake.exe" @('--build',$build,'--target','sunshine',"-j$Jobs")
}finally{Pop-Location}
Run "$prefix\bin\g++.exe" @('-std=c++20','-O2','-Wall','-Wextra','-Werror','-static','-I',$source,'-I',"$source\third-party\moonlight-common-c\src","$PSScriptRoot\ValidationTests.cpp",'-o',"$build\InputValidationTests.exe",'-luser32')
Run "$build\InputValidationTests.exe" @()
Copy-Item -LiteralPath "$build\sunshine.exe" -Destination "$stage\sunshine.exe" -Force
Run "$prefix\bin\strip.exe" @('--strip-unneeded',"$stage\sunshine.exe")
Get-ChildItem -LiteralPath "$source\src_assets\common\assets" -File | Where-Object {$_.Name -ne 'apps.json'} | Copy-Item -Destination "$stage\assets" -Force
Copy-Item -LiteralPath "$source\src_assets\windows\assets\shaders" -Destination "$stage\assets" -Recurse -Force
Copy-Item -LiteralPath "$source\LICENSE" -Destination "$stage\SUNSHINE-LICENSE.txt" -Force
& "$PSScriptRoot\PrepareSources.ps1" -WorkDirectory $work
& "$PSScriptRoot\CopyNotices.ps1" -WorkDirectory $work
Write-Output "Engine staged at $stage. Run Tools\Pack-Engine.ps1 to embed it in the single-file installer."
Write-Output 'This script builds files only. It never starts an engine, driver, service or capture session.'
