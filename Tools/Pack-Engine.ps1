param([Parameter(Mandatory=$true)][string]$EngineDirectory,[string]$OutputDirectory)
$ErrorActionPreference='Stop'
$engineRoot=(Resolve-Path -LiteralPath $EngineDirectory).Path
if(!$OutputDirectory){$OutputDirectory=Join-Path $PSScriptRoot '..\obj\Payload'}
$outputRoot=[IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
$files=@(Get-ChildItem -LiteralPath $engineRoot -Recurse -File | Sort-Object FullName)
if(!$files.Count -or $files.Count -gt 2048){throw 'Invalid engine file count'}
$manifest=[Collections.Generic.List[string]]::new();$manifest.Add('RDC-ENGINE-1')
$ddf=[Collections.Generic.List[string]]::new()
foreach($line in @('.OPTION EXPLICIT','.Set CabinetNameTemplate=Engine.cab',('.Set DiskDirectoryTemplate="'+$outputRoot+'"'),('.Set InfFileName="'+(Join-Path $outputRoot 'Engine.inf')+'"'),('.Set RptFileName="'+(Join-Path $outputRoot 'Engine.rpt')+'"'),'.Set MaxDiskSize=0','.Set Cabinet=ON','.Set Compress=ON','.Set CompressionType=MSZIP','.Set MaxCabinetSize=0','.Set MaxDiskFileCount=0','.Set UniqueFiles=ON')){$ddf.Add($line)}
$total=[uint64]0
foreach($file in $files){
 if($file.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Redirected engine file refused'}
 $relative=$file.FullName.Substring($engineRoot.Length+1).Replace('\','/')
 if($relative -notmatch '^[A-Za-z0-9_.\-/]+$' -or $relative.Contains('..') -or $relative.Length -gt 240){throw 'Invalid relative engine file'}
 if($file.Length -gt 128MB){throw 'Engine file exceeds128MB'};$total+=$file.Length
 if($total -gt 512MB){throw 'Engine exceeds512MB'}
 $hash=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
 $manifest.Add(([string]$file.Length)+"`t"+$hash+"`t"+$relative)
 $ddf.Add('"'+$file.FullName+'" "'+$relative.Replace('/','\')+'"')
}
$manifestPath=Join-Path $outputRoot 'Engine.manifest';$ddfPath=Join-Path $outputRoot 'Engine.ddf'
[IO.File]::WriteAllText($manifestPath,($manifest -join "`n")+"`n",[Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($ddfPath,($ddf -join "`r`n")+"`r`n",[Text.UTF8Encoding]::new($false))
& "$env:WINDIR\System32\makecab.exe" /F $ddfPath > (Join-Path $outputRoot 'MakeCab.log')
if($LASTEXITCODE){throw 'Engine cabinet creation failed'}
[pscustomobject]@{Cabinet=(Join-Path $outputRoot 'Engine.cab');Manifest=$manifestPath;Files=$files.Count;UncompressedBytes=$total}
