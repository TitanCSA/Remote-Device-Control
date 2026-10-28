param([Parameter(Mandatory=$true)][string]$WorkDirectory)
$ErrorActionPreference='Stop'
$stage=Join-Path $WorkDirectory 'Payload\Engine\Notices'
$source=Join-Path $WorkDirectory 'Upstream\Sunshine'
$prefix=Join-Path $WorkDirectory 'ThirdParty\SunshineDeps\root\ucrt64'
New-Item -ItemType Directory -Path $stage -Force | Out-Null
New-Item -ItemType Directory -Path "$stage\MSYS2" -Force | Out-Null
Get-ChildItem -LiteralPath "$prefix\share\licenses" | Copy-Item -Destination "$stage\MSYS2" -Recurse -Force
Copy-Item -LiteralPath "$prefix\share\icu\78.2\LICENSE" -Destination "$stage\ICU-LICENSE.txt" -Force
$components=@{
 Sunshine=$source
 Moonlight="$source\third-party\moonlight-common-c"
 ENet="$source\third-party\moonlight-common-c\enet"
 SimpleWebServer="$source\third-party\Simple-Web-Server"
 LibDisplayDevice="$source\third-party\libdisplaydevice"
 Nanors="$source\third-party\nanors"
 NvCodec="$source\third-party\nv-codec-headers"
 Boost=(Join-Path $WorkDirectory 'SunshineBuild\_deps\boost-src')
 Json=(Join-Path $WorkDirectory 'SunshineBuild\_deps\json-src')
}
$codecs=Join-Path $WorkDirectory 'Upstream\SunshineCodecSources\third-party\FFmpeg'
foreach($name in @('FFmpeg','x264','x265_git','SVT-AV1','AMF','nv-codec-headers')){$components["Codec-$name"]=Join-Path $codecs $name}
foreach($entry in $components.GetEnumerator()){
 if(!(Test-Path -LiteralPath $entry.Value)){throw "Missing dependency source for notices: $($entry.Key). Run PrepareSources.ps1 first."}
 $target=Join-Path $stage $entry.Key
 New-Item -ItemType Directory -Path $target -Force | Out-Null
 Get-ChildItem -LiteralPath $entry.Value -File | Where-Object {$_.Name -match '^(LICENSE|LICENCE|COPYING|NOTICE|PATENTS|COPYRIGHT)'} | Copy-Item -Destination $target -Force
}
$nvapi=Get-Content -LiteralPath "$source\third-party\nvapi-open-source-sdk\nvapi.h" -TotalCount 27
[IO.File]::WriteAllLines((Join-Path $stage 'NVIDIA-NvAPI-MIT.txt'),$nvapi,[Text.UTF8Encoding]::new($false))
Copy-Item -LiteralPath "$PSScriptRoot\README.md" -Destination "$stage\Source-and-Changes.md" -Force
Write-Output "Dependency notices copied to $stage"
