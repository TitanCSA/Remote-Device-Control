param([string]$WorkDirectory)
$ErrorActionPreference='Stop'
if(!$WorkDirectory){$WorkDirectory=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\obj'))}
$codec=Join-Path $WorkDirectory 'Upstream\SunshineCodecSources'
$iconv=Join-Path $WorkDirectory 'Upstream\LibiconvSource'
function Git([string[]]$Arguments){& git.exe @Arguments;if($LASTEXITCODE){throw 'Corresponding source checkout failed'}}
if(!(Test-Path -LiteralPath "$codec\.git")){
 New-Item -ItemType Directory -Path (Split-Path -Parent $codec) -Force | Out-Null
 Git @('clone','--filter=blob:none','--no-checkout','https://github.com/LizardByte/build-deps.git',$codec)
 Git @('-C',$codec,'fetch','--depth','1','origin','2851db101eeddae8f02489d48a52a4d83e6f7e7b')
 Git @('-C',$codec,'checkout','--detach','FETCH_HEAD')
}
$pin=& git.exe -C $codec rev-parse HEAD
if($pin -ne '2851db101eeddae8f02489d48a52a4d83e6f7e7b'){throw 'Unexpected codec source revision; select an empty work directory'}
Git @('-C',$codec,'submodule','update','--init','--depth','1','--jobs','4')
New-Item -ItemType Directory -Path $iconv -Force | Out-Null
$recipe='https://raw.githubusercontent.com/msys2/MINGW-packages/f89ccd3564cceff9ed46d778c91f278381393c75/mingw-w64-libiconv/'
foreach($name in @('PKGBUILD','0003-add-cp65001-as-utf8-alias.patch','0002-fix-cr-for-awk-in-configure.all.patch','fix-pointer-buf.patch','iconv.pc')){
 Invoke-WebRequest -Uri ($recipe+$name) -UseBasicParsing -OutFile (Join-Path $iconv $name)
}
$archive=Join-Path $iconv 'libiconv-1.18.tar.gz'
$expected='3b08f5f4f9b4eb82f151a7040bfd6fe6c6fb922efe4b1659c66ea933276965e8'
if(!(Test-Path -LiteralPath $archive) -or (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $expected){
 & "$env:WINDIR\System32\curl.exe" --fail --location --silent --show-error --max-time 120 --output $archive 'https://ftp.gnu.org/pub/gnu/libiconv/libiconv-1.18.tar.gz'
 if($LASTEXITCODE){throw 'libiconv source download failed'}
}
if((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $expected){throw 'libiconv source integrity failure'}
Write-Output 'Matching codec and libiconv sources are ready for redistribution.'
