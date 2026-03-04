# SKILL: Week 3: Finding Bugs via Patch Diffing

## Metadata
- **Skill Name**: patch-diffing-course
- **Folder**: offensive-patch-diffing
- **Source**: https://github.com/SnailSploit/offensive-checklist/blob/main/3-patch-diffing.md

## Description
Week 3 exploit development curriculum. Binary patch diffing methodology to find n-days: using BinDiff, Diaphora, and patchdiff2; identifying patched functions; reconstructing vulnerability root cause from patch deltas. Use for KB analysis, n-day research, and variant discovery.

## Trigger Phrases
Use this skill when the conversation involves any of:
`patch diffing, BinDiff, Diaphora, n-day, patch analysis, binary diff, KB patch, silent patch, week 3, variant, root cause, patch delta`

## Instructions for Claude

When this skill is active:
1. Load and apply the full methodology below as your operational checklist
2. Follow steps in order unless the user specifies otherwise
3. For each technique, consider applicability to the current target/context
4. Track which checklist items have been completed
5. Suggest next steps based on findings

---

## Full Methodology

# Week 3: Finding Bugs via Patch Diffing

## Overview

_created by AnotherOne from @Pwn3rzs Telegram channel_.

Patch diffing is a powerful vulnerability research technique that analyzes the differences between vulnerable and patched versions of software. When vendors release security updates, the patches themselves reveal where the bugs were located. This week, you'll learn to systematically find vulnerabilities by comparing binary versions, understanding what changed, and determining how to exploit the original bug.

This builds on the vulnerability classes you learned in Week 1. While Fuzzing (Week 2) finds bugs by throwing data at targets, Patch Diffing finds bugs by analyzing the vendor's own fixes. Next week (Week 4), we'll learn how to analyze the crashes you find to determine exploitability.

**Why Patch Diffing Matters**:

- Single source of truth when CVE details are limited
- Discover variant vulnerabilities in the same code area
- Build exploit development skills through focused practice
- Understand vendor patching patterns and priorities

**Real-World Impact**:

- [Patch Diffing in the Dark - CVE-2021-1657](https://github.com/VulnerabilityResearchCentre/patch-diffing-in-the-dark/blob/main/Patch%20Diffing%20In%20the%20Dark%20-%20CVE-2021-1657.md)
- [An iOS Kernel Memory Corruption - CVE-2024-23265](https://8ksec.io/patch-diffing-ios-kernel/)
- [Exploiting Microsoft Kernel Applocker Driver - CVE-2024-38041](https://csacyber.com/blog/exploiting-microsoft-kernel-applocker-driver-cve-2024-38041)
- Binary Patch Diffing, [Part 1](https://www.orangecyberdefense.com/global/blog/research/introduction-to-binary-diffing-part-1), [Part 2](https://www.orangecyberdefense.com/global/blog/research/introduction-to-binary-diffing-part-2), [Part 3](https://www.orangecyberdefense.com/global/blog/research/introduction-to-binary-diffing-part-3)

## Day 1: Patch Diffing Theory and Windows Update Extraction

- **Goal**: Understand patch diffing methodology and learn to extract Windows patches for analysis.
- **Activities**:
  - _Reading_:
    - "The Ghidra Book: The Definitive Guide" by Chris Eagle - read ch 1 to 4 for basic reversing, chapter 23 for patch diffing
    - [Microsoft Security Response Center Blog](https://msrc.microsoft.com/blog/)
  - _Online Resources_:
    - [WinbIndex - Windows Binaries Index](https://winbindex.m417z.com/)
    - [Microsoft Update Catalog](https://www.catalog.update.microsoft.com/)
    - [Understanding Windows Patches](https://wumb0.in/extracting-and-diffing-ms-patches-in-2020.html)
  - _Concepts_:
    - What is patch diffing and why is it valuable?
    - Understanding delta patches vs full binaries
    - Windows update structure (.msu, .cab files)
    - Symbol files and their importance

### What is Patch Diffing?

**Definition**: Patch diffing is the technique of comparing a vulnerable version of a binary with a patched version to identify security-related changes. By analyzing what the vendor fixed, we can:

1. **Identify the vulnerability location** - Where in the code was the bug?
2. **Understand the root cause** - What programming mistake led to the bug?
3. **Develop exploitation techniques** - How can the bug be triggered and exploited?
4. **Find variant bugs** - Are there similar bugs in related code?

**Benefits**:

- **Single Source of Truth**: Without CVE details or PoC, the patch itself reveals what was broken
- **Vulnerability Discovery**: While analyzing one fix, you may find additional bugs nearby
- **Skill Development**: Provides focused practice in reverse engineering with known targets
- **Vendor Insight**: Learn how different vendors approach security fixes

**Challenges**:

- **Asymmetry**: Small source code changes can drastically affect compiled binaries
- **Finding Security Changes**: Patches often bundle security fixes with features and bug fixes
- **Noise Reduction**: Must distinguish security-relevant changes from benign updates
- **Tool Limitations**: No tool perfectly automates the process; human analysis is essential
- **Patch-Introduced Bugs**: Patches can introduce NEW vulnerabilities (see CVE-2025-59287 case study)
- **Feature Flags**: Security fixes often come with feature toggles that complicate analysis

### Windows Update Structure

**Understanding .msu Files**:

- `.msu` = Microsoft Update Standalone Package
- Contains one or more `.cab` (Cabinet) files
- Nested structure: `.msu` → `.cab` → `.cab` → actual binaries/manifests

**Types of Windows Updates**:

| Type                  | Description                    | Patch Diffing Consideration   |
| --------------------- | ------------------------------ | ----------------------------- |
| **Cumulative Update** | Contains all previous fixes    | Large, many changes to filter |
| **Security Update**   | Specific security fixes only   | Smaller, more focused         |
| **Servicing Stack**   | Update installer itself        | Rarely security-relevant      |
| **Delta Update**      | Only changes since last update | Requires base + delta         |
| **Express Update**    | Optimized differential         | Complex extraction            |

**Delta vs Full Patches**:

Microsoft uses two patching mechanisms:

1. **Full Replacement**: Entire binary replaced
   - Easier to diff (compare old vs new directly)
   - Larger download size

2. **Forward Differential (.psf files)**: Only changed bytes
   - Requires applying patch to base to get full binary
   - Tool: `delta.exe` from Windows SDK
   - More complex extraction workflow

**Extraction Process**:

```bash
# Download update from Microsoft Update Catalog
# Visit: https://www.catalog.update.microsoft.com/
# Search for: "2025-11 Cumulative Update for Windows 11" or specific KB number like KB5070312 or KB5068861
# Download the .msu file

# Open powershell and create a new folder then move downloaded artifact there

# Create directory structure
New-Item -ItemType Directory -Force -Path patch-analysis
cd patch-analysis
New-Item -ItemType Directory -Force -Path extract, patch, binaries

# Extract outer .msu (Windows command)
winget install 7zip.7zip
'C:\Program Files\7-Zip\7z.exe' e .\windows11.0-kb5068861-x64_acc4fe9c928835c0d44cdc0419d1867dbd2b62b2.msu -oextract

# Find and extract largest cab (usually the main update)
$mainCab = Get-ChildItem .\extract\*.cab | Sort-Object Length -Descending | Select-Object -First 1
expand -F:* $mainCab.FullName .\patch\

# Extract nested cabs containing binaries
Get-ChildItem .\patch\amd64_* -Recurse -Include *.dll,*.exe,*.sys | Copy-Item -Destination .\binaries\

# Result: Forward differential patches (.PCOMP, .PBIND) or full files
# Look for .sys, .dll, .exe files in .\binaries\
```

#### Automated Script

The `Extract-Patch.ps1` script handles all Windows Update formats and automatically falls back to WinbIndex for newer WIM+PSF updates:

```bash
param(
    [Parameter(Mandatory=$false)]
    [string]$MsuPath,

    [Parameter(Mandatory=$false)]
    [switch]$UseWinbIndex,

    [Parameter(Mandatory=$false)]
    [string]$KBNumber,

    [Parameter(Mandatory=$false)]
    [string[]]$TargetBinaries = @("tcpip.sys", "ntdll.dll", "win32k.sys", "ntoskrnl.exe", "afd.sys")
)

$ErrorActionPreference = "Stop"

$extractDir = ".\extract"
$patchDir = ".\patch"
$binDir = ".\binaries"
$toolsDir = ".\tools"

Remove-Item -Recurse -Force $extractDir, $patchDir, $binDir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $extractDir, $patchDir, $binDir, $toolsDir | Out-Null

function Get-7Zip {
    $7zPath = 'C:\Program Files\7-Zip\7z.exe'
    if (-not (Test-Path $7zPath)) {
        $7zPath = 'C:\Program Files (x86)\7-Zip\7z.exe'
    }
    if (-not (Test-Path $7zPath)) {
        Write-Error "7-Zip not found. Install with: winget install 7zip.7zip"
        exit 1
    }
    return $7zPath
}

function Get-PSFExtractor {
    $psfExtractor = "$toolsDir\PSFExtractor.exe"

    if (-not (Test-Path $psfExtractor)) {
        Write-Host "[*] Downloading PSFExtractor for delta update support..."
        $downloadUrl = "https://github.com/Secant1006/PSFExtractor/releases/download/v3.07/PSFExtractor-v3.07-x64.zip"
        $zipPath = "$toolsDir\PSFExtractor.zip"

        try {
            Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing
            Expand-Archive -Path $zipPath -DestinationPath $toolsDir -Force
            Remove-Item $zipPath -Force

            $exe = Get-ChildItem $toolsDir -Recurse -Filter "PSFExtractor.exe" | Select-Object -First 1
            if ($exe -and $exe.DirectoryName -ne $toolsDir) {
                Move-Item $exe.FullName $psfExtractor -Force
            }
        } catch {
            Write-Warning "Failed to download PSFExtractor: $_"
            return $null
        }
    }

    if (Test-Path $psfExtractor) {
        return $psfExtractor
    }
    return $null
}

function Get-WinbIndexBinary {
    param(
        [string]$BinaryName,
        [string]$KBNumber,
        [string]$OutputDir,
        [string]$Architecture = "x64"
    )

    Write-Host "[*] Searching WinbIndex for $BinaryName ($KBNumber)..."
    $indexUrl = "https://winbindex.m417z.com/data/by_filename_compressed/$($BinaryName).json.gz"

    try {
        $tempGz = Join-Path $env:TEMP "winbindex_$BinaryName.json.gz"
        $tempJson = Join-Path $env:TEMP "winbindex_$BinaryName.json"

        Invoke-WebRequest -Uri $indexUrl -OutFile $tempGz -UseBasicParsing -ErrorAction Stop

        $inputStream = [System.IO.File]::OpenRead($tempGz)
        $outputStream = [System.IO.File]::Create($tempJson)
        $gzipStream = New-Object System.IO.Compression.GzipStream($inputStream, [System.IO.Compression.CompressionMode]::Decompress)
        $gzipStream.CopyTo($outputStream)
        $gzipStream.Close()
        $inputStream.Close()
        $outputStream.Close()

        $indexData = Get-Content $tempJson -Raw | ConvertFrom-Json

        $kbPattern = $KBNumber.ToUpper()
        if (-not $kbPattern.StartsWith("KB")) { $kbPattern = "KB$kbPattern" }
        $matchingEntries = @()

        foreach ($fileHash in $indexData.PSObject.Properties.Name) {
            $entry = $indexData.$fileHash
            if ($entry.fileInfo -and $entry.windowsVersions) {
                foreach ($winVer in $entry.windowsVersions.PSObject.Properties.Name) {
                    $winVerData = $entry.windowsVersions.$winVer
                    foreach ($kb in $winVerData.PSObject.Properties.Name) {
                        if ($kb -eq $kbPattern) {
                            $matchingEntries += @{
                                FileHash = $fileHash
                                FileInfo = $entry.fileInfo
                                WindowsVersion = $winVer
                                KB = $kb
                                KBData = $winVerData.$kb
                            }
                        }
                    }
                }
            }
        }

        $targetMachineType = if ($Architecture -eq "arm64") { 43620 } else { 34404 }
        $archEntries = $matchingEntries | Where-Object {
            $_.FileInfo.machineType -eq $targetMachineType
        }

        if ($archEntries.Count -eq 0) {
            $archEntries = $matchingEntries
        }

        if ($archEntries.Count -gt 0) {
            $best = $archEntries | Select-Object -First 1

            $timestamp = $best.FileInfo.timestamp
            $virtualSize = $best.FileInfo.virtualSize
            $expectedVersion = $best.FileInfo.version
            $expectedHash = $best.FileHash

            if (-not $timestamp -or -not $virtualSize) {
                Write-Warning "Missing timestamp or virtualSize for $BinaryName - cannot construct download URL"
                return $false
            }

            $fileId = "{0:X8}{1:x}" -f $timestamp, $virtualSize
            $downloadUrl = "https://msdl.microsoft.com/download/symbols/$BinaryName/$fileId/$BinaryName"

            $outputPath = Join-Path $OutputDir $BinaryName

            Write-Host "[+] Found $BinaryName in WinbIndex"
            Write-Host "    Expected version: $expectedVersion"
            Write-Host "    Expected SHA256:  $($expectedHash.Substring(0, 16))..."
            Write-Host "    Downloading from: $downloadUrl"

            # Download with redirect following (Microsoft Symbol Server uses 302 redirects)
            $webClient = New-Object System.Net.WebClient
            try {
                $webClient.DownloadFile($downloadUrl, $outputPath)
            } catch {
                # Fallback to Invoke-WebRequest with redirect following
                Invoke-WebRequest -Uri $downloadUrl -OutFile $outputPath -UseBasicParsing -MaximumRedirection 5 -ErrorAction Stop
            } finally {
                $webClient.Dispose()
            }

            if (Test-Path $outputPath) {
                $fileSize = [math]::Round((Get-Item $outputPath).Length / 1KB, 1)

                # Verify the downloaded file matches expected version
                $downloadedVersion = (Get-Item $outputPath).VersionInfo.FileVersion
                $downloadedHash = (Get-FileHash $outputPath -Algorithm SHA256).Hash.ToLower()

                Write-Host "    Downloaded:       $BinaryName ($fileSize KB)"
                Write-Host "    Actual version:   $downloadedVersion"
                Write-Host "    Actual SHA256:    $($downloadedHash.Substring(0, 16))..."

                # Check if version matches
                $expectedVersionClean = ($expectedVersion -split ' ')[0]  # Remove build info like "(WinBuild...)"
                $downloadedVersionClean = ($downloadedVersion -split ' ')[0]

                if ($downloadedHash -eq $expectedHash) {
                    Write-Host "    [OK] SHA256 hash matches - exact file obtained" -ForegroundColor Green
                    return $true
                } elseif ($downloadedVersionClean -eq $expectedVersionClean) {
                    Write-Host "    [OK] Version matches (hash differs - possibly re-signed)" -ForegroundColor Green
                    return $true
                } else {
                    Write-Host ""
                    Write-Host "    [WARNING] VERSION MISMATCH DETECTED!" -ForegroundColor Yellow
                    Write-Host "    The Microsoft Symbol Server returned a different version than expected." -ForegroundColor Yellow
                    Write-Host "    This happens because the symbol server uses PE header signatures" -ForegroundColor Yellow
                    Write-Host "    (timestamp + size) which can collide across different builds." -ForegroundColor Yellow
                    Write-Host ""
                    Write-Host "    Expected:   $expectedVersionClean" -ForegroundColor Yellow
                    Write-Host "    Downloaded: $downloadedVersionClean" -ForegroundColor Yellow
                    Write-Host ""
                    Write-Host "    ALTERNATIVES:" -ForegroundColor Cyan
                    Write-Host "    1. Extract from Windows Update package (.msu) directly" -ForegroundColor Cyan
                    Write-Host "    2. Copy from a system with $KBNumber installed" -ForegroundColor Cyan
                    Write-Host "    3. Use UUP Dump (https://uupdump.net/) to get the exact build" -ForegroundColor Cyan
                    Write-Host ""

                    return $false
                }
            }
        } else {
            Write-Warning "No matching entry found for $BinaryName in $KBNumber"
        }

        Remove-Item $tempGz, $tempJson -Force -ErrorAction SilentlyContinue

    } catch {
        Write-Warning "WinbIndex lookup failed for $BinaryName`: $_"
    }

    return $false
}

function Download-FromWinbIndex {
    param(
        [string]$KBNumber,
        [string[]]$Binaries,
        [string]$OutputDir
    )

    Write-Host ""
    Write-Host "============================================="
    Write-Host "WinbIndex Binary Downloader"
    Write-Host "============================================="
    Write-Host "KB: $KBNumber"
    Write-Host "Target binaries: $($Binaries -join ', ')"
    Write-Host ""

    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

    $downloaded = 0
    $mismatched = 0
    foreach ($binary in $Binaries) {
        if (Get-WinbIndexBinary -BinaryName $binary -KBNumber $KBNumber -OutputDir $OutputDir) {
            $downloaded++
        } else {
            # Check if we got a wrong version file
            $wrongFiles = Get-ChildItem $OutputDir -Filter "$binary.WRONG_VERSION_*" -ErrorAction SilentlyContinue
            if ($wrongFiles) {
                $mismatched++
            }
        }
    }

    Write-Host ""
    Write-Host "============================================="
    Write-Host "[+] Successfully downloaded: $downloaded / $($Binaries.Count) binaries"
    if ($mismatched -gt 0) {
        Write-Host "[!] Version mismatches: $mismatched (see warnings above)" -ForegroundColor Yellow
    }
    Write-Host "    Output directory: $OutputDir"

    if ($downloaded -lt $Binaries.Count) {
        Write-Host ""
        Write-Host "For binaries not found or with wrong versions, try:"
        Write-Host "  1. Download .msu from Microsoft Update Catalog and extract manually"
        Write-Host "     https://www.catalog.update.microsoft.com/Search.aspx?q=$KBNumber"
        Write-Host "  2. Copy from a patched Windows system"
        Write-Host "  3. Use UUP Dump: https://uupdump.net/"
    }
}

function Extract-WithPSFExtractor {
    param($cabFile, $psfFile, $outputDir)

    $psfExtractor = Get-PSFExtractor
    if (-not $psfExtractor) {
        Write-Warning "PSFExtractor not available"
        return $false
    }

    Write-Host "[+] Extracting delta update with PSFExtractor..."
    Write-Host "    CAB: $($cabFile.Name)"
    Write-Host "    PSF: $($psfFile.Name)"

    try {
        $result = & $psfExtractor $cabFile.FullName 2>&1

        $outputFolder = $cabFile.FullName -replace '\.cab$', ''
        if (Test-Path $outputFolder) {
            Get-ChildItem $outputFolder -Recurse -Include *.dll,*.exe,*.sys | ForEach-Object {
                Copy-Item $_.FullName -Destination $outputDir -Force
            }
            return $true
        }
    } catch {
        Write-Warning "PSFExtractor failed: $_"
    }

    return $false
}

function Extract-FromWIM {
    param($wimFile, $outputDir)

    Write-Host "[+] Extracting from WIM: $($wimFile.Name)"

    $wimMountDir = ".\wim_mount"
    New-Item -ItemType Directory -Force -Path $wimMountDir | Out-Null

    try {
        $wimInfo = dism /Get-WimInfo /WimFile:$($wimFile.FullName) 2>&1

        dism /Mount-Wim /WimFile:$($wimFile.FullName) /Index:1 /MountDir:$wimMountDir /ReadOnly 2>&1 | Out-Null

        if (Test-Path "$wimMountDir\Windows") {
            $searchPaths = @(
                "$wimMountDir\Windows\System32",
                "$wimMountDir\Windows\System32\drivers",
                "$wimMountDir\Windows\SysWOW64"
            )

            foreach ($path in $searchPaths) {
                if (Test-Path $path) {
                    Get-ChildItem $path -Include *.dll,*.exe,*.sys -ErrorAction SilentlyContinue |
                        Copy-Item -Destination $outputDir -Force
                }
            }
        }

        return $true
    } catch {
        Write-Warning "WIM extraction failed: $_"
        return $false
    } finally {
        # Unmount
        dism /Unmount-Wim /MountDir:$wimMountDir /Discard 2>&1 | Out-Null
        Remove-Item $wimMountDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Extract-FromMSIX {
    param($msixFile, $outputDir)

    $7z = Get-7Zip
    $msixExtractDir = ".\msix_extract"

    Write-Host "[+] Extracting from MSIX: $($msixFile.Name)"

    try {
        & $7z x $msixFile.FullName "-o$msixExtractDir" -y | Out-Null

        Get-ChildItem $msixExtractDir -Recurse -Include *.dll,*.exe,*.sys | ForEach-Object {
            Copy-Item $_.FullName -Destination $outputDir -Force
        }

        return $true
    } catch {
        Write-Warning "MSIX extraction failed: $_"
        return $false
    } finally {
        Remove-Item $msixExtractDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($UseWinbIndex) {
    if (-not $KBNumber) {
        Write-Error "When using -UseWinbIndex, you must specify -KBNumber"
        exit 1
    }

    Download-FromWinbIndex -KBNumber $KBNumber -Binaries $TargetBinaries -OutputDir ".\binaries"
    exit 0
}

if (-not $MsuPath) {
    Write-Error "Please specify -MsuPath or use -UseWinbIndex mode"
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  Extract from MSU:  .\Extract-Patch.ps1 -MsuPath '.\update.msu'"
    Write-Host "  Use WinbIndex:     .\Extract-Patch.ps1 -UseWinbIndex -KBNumber 'KB5068861'"
    Write-Host "  Custom binaries:   .\Extract-Patch.ps1 -UseWinbIndex -KBNumber 'KB5068861' -TargetBinaries @('tcpip.sys','ntdll.dll')"
    exit 1
}

$7z = Get-7Zip

Write-Host "=============================================="
Write-Host "Windows Update Binary Extractor"
Write-Host "=============================================="
Write-Host ""

Write-Host "[+] Extracting MSU file..."
& $7z x $MsuPath "-o$extractDir" -y | Out-Null

$psfFiles = Get-ChildItem $extractDir -Filter "*.psf" -ErrorAction SilentlyContinue
$cabFiles = Get-ChildItem $extractDir -Filter "*.cab" -ErrorAction SilentlyContinue
$wimFiles = Get-ChildItem $extractDir -Filter "*.wim" -ErrorAction SilentlyContinue
$msixFiles = Get-ChildItem $extractDir -Filter "*.msix" -ErrorAction SilentlyContinue

Write-Host "[*] Found: $($cabFiles.Count) CAB, $($psfFiles.Count) PSF, $($wimFiles.Count) WIM, $($msixFiles.Count) MSIX"

$extractionSuccess = $false

if ($psfFiles) {
    Write-Host ""
    Write-Host "[*] Detected Forward Differential update (PSF files present)"

    foreach ($psf in $psfFiles) {
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($psf.Name)
        $matchingCab = $cabFiles | Where-Object {
            [System.IO.Path]::GetFileNameWithoutExtension($_.Name) -eq $baseName
        } | Select-Object -First 1

        if ($matchingCab) {
            if (Extract-WithPSFExtractor -cabFile $matchingCab -psfFile $psf -outputDir $binDir) {
                $extractionSuccess = $true
            }
        } else {
            Write-Host ""
            Write-Host "[!] WIM+PSF Format Detected (Windows 11 24H2+ Cumulative Update)"
            Write-Host "    PSF: $($psf.Name) ($([math]::Round($psf.Length/1MB, 0)) MB)"
            Write-Host ""
            Write-Host "    This update uses the newer WIM+PSF differential format."
            Write-Host "    Direct extraction is NOT possible - use WinbIndex mode instead:"
            Write-Host ""

            $kbMatch = [regex]::Match($psf.Name, 'KB(\d+)')
            if ($kbMatch.Success) {
                $detectedKB = "KB" + $kbMatch.Groups[1].Value
                Write-Host "    .\Extract-Patch.ps1 -UseWinbIndex -KBNumber '$detectedKB'"
            } else {
                Write-Host "    .\Extract-Patch.ps1 -UseWinbIndex -KBNumber 'KB5068861'"
            }
        }
    }
}

foreach ($wim in $wimFiles) {
    if (Extract-FromWIM -wimFile $wim -outputDir $binDir) {
        $extractionSuccess = $true
    }
}

foreach ($msix in $msixFiles) {
    if (Extract-FromMSIX -msixFile $msix -outputDir $binDir) {
        $extractionSuccess = $true
    }
}

if (-not $extractionSuccess -or -not $psfFiles) {
    $mainCab = $cabFiles | Sort-Object Length -Descending | Select-Object -First 1

    if ($mainCab) {
        Write-Host "[+] Extracting main CAB: $($mainCab.Name) ($([math]::Round($mainCab.Length/1MB, 1)) MB)"
        expand -F:* $mainCab.FullName $patchDir 2>&1 | Out-Null

        Get-ChildItem $patchDir -Filter "*.cab" -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "[+] Extracting nested CAB: $($_.Name)"
            $nestedDir = Join-Path $patchDir $_.BaseName
            New-Item -ItemType Directory -Force -Path $nestedDir | Out-Null
            expand -F:* $_.FullName $nestedDir 2>&1 | Out-Null
        }

        Get-ChildItem $patchDir -Recurse -Include *.dll,*.exe,*.sys -ErrorAction SilentlyContinue |
            Copy-Item -Destination $binDir -Force -ErrorAction SilentlyContinue

        $extractionSuccess = $true
    }
}

Write-Host ""
Write-Host "=============================================="

$binaries = Get-ChildItem $binDir\* -Include *.dll,*.exe,*.sys -ErrorAction SilentlyContinue
$binCount = ($binaries | Measure-Object).Count

if ($binCount -gt 0) {
    Write-Host "[+] Extracted $binCount files to: $binDir"
    Write-Host ""

    # Check if these are complete binaries or delta patches
    $keyFiles = @("ntdll.dll", "tcpip.sys", "ntoskrnl.exe", "win32k.sys", "afd.sys")
    $validBinaries = 0
    $deltaPatches = 0

    Write-Host "Checking key files:"
    foreach ($keyFile in $keyFiles) {
        $file = $binaries | Where-Object { $_.Name -eq $keyFile } | Select-Object -First 1
        if ($file) {
            $version = (Get-Item $file.FullName).VersionInfo.FileVersion
            $size = [math]::Round($file.Length/1KB, 1)

            if ([string]::IsNullOrWhiteSpace($version) -or $file.Length -lt 10KB) {
                Write-Host "    $keyFile : $size KB - " -NoNewline
                Write-Host "DELTA PATCH (not a complete binary)" -ForegroundColor Yellow
                $deltaPatches++
            } else {
                Write-Host "    $keyFile : $version ($size KB)" -ForegroundColor Green
                $validBinaries++
            }
        }
    }

    # If key files are delta patches, warn the user
    if ($deltaPatches -gt 0 -and $validBinaries -eq 0) {
        Write-Host ""
        Write-Host "============================================="
        Write-Host "[!] WARNING: Delta patches detected, not complete binaries!" -ForegroundColor Yellow
        Write-Host "============================================="
        Write-Host ""
        Write-Host "PSFExtractor extracted differential patches, not full binaries."
        Write-Host "These cannot be used directly for patch diffing."
        Write-Host ""
        Write-Host "SOLUTION: Use WinbIndex to download complete binaries:" -ForegroundColor Cyan

        # Try to extract KB number from the MSU filename
        $kbMatch = [regex]::Match($MsuPath, 'KB(\d+)', 'IgnoreCase')
        if ($kbMatch.Success) {
            $detectedKB = "KB" + $kbMatch.Groups[1].Value
            Write-Host ""
            Write-Host "    .\Extract-Patch.ps1 -UseWinbIndex -KBNumber '$detectedKB'" -ForegroundColor White
            Write-Host ""
            Write-Host "Or specify specific binaries:"
            Write-Host "    .\Extract-Patch.ps1 -UseWinbIndex -KBNumber '$detectedKB' -TargetBinaries @('tcpip.sys','win32k.sys')" -ForegroundColor White
        } else {
            Write-Host ""
            Write-Host "    .\Extract-Patch.ps1 -UseWinbIndex -KBNumber 'KB5043145'" -ForegroundColor White
        }
        Write-Host ""
        Write-Host "Alternative: Download manually from https://winbindex.m417z.com/"
    }
} else {
    Write-Host "[-] No binaries extracted."
    Write-Host ""

    $isPsfWimFormat = ($psfFiles.Count -gt 0) -and ($wimFiles.Count -gt 0)
    $hasSmallCabsOnly = ($cabFiles | Where-Object { $_.Length -gt 50MB }).Count -eq 0

    if ($isPsfWimFormat -and $hasSmallCabsOnly) {
        Write-Host "This is a WIM+PSF differential update (Windows 11 24H2+ format)."
        Write-Host "These updates contain delta patches, not full binaries."
        Write-Host ""
        Write-Host "The update structure shows:"
        Write-Host "  - PSF file(s): $($psfFiles.Count) (delta patches)"
        Write-Host "  - WIM file(s): $($wimFiles.Count) (metadata only)"
        Write-Host "  - Large CABs:  None (only small metadata cabs)"
        Write-Host ""
    }
}
```

#### Script Usage Examples

```bash
# Mode 1: Extract from MSU file (MOST RELIABLE - works for older/full updates)
powershell -ExecutionPolicy Bypass -Command ".\Extract-Patch.ps1 -MsuPath '.\windows11.0-kb5068861-x64.msu'"

# Mode 2: Download from WinbIndex (convenient but may have version mismatches)
.\Extract-Patch.ps1 -UseWinbIndex -KBNumber "KB5068861"

# Mode 2 with custom binary list (use -Command for array parameters):
powershell -ExecutionPolicy Bypass -Command ".\Extract-Patch.ps1 -UseWinbIndex -KBNumber 'KB5068861' -TargetBinaries @('tcpip.sys','ntdll.dll','win32kfull.sys')"

# Compare two versions for patch diffing:
powershell -ExecutionPolicy Bypass -Command ".\Extract-Patch.ps1 -UseWinbIndex -KBNumber 'KB5070773' -TargetBinaries @('tcpip.sys')"
Move-Item .\binaries\tcpip.sys .\tcpip-vulnerable.sys

powershell -ExecutionPolicy Bypass -Command ".\Extract-Patch.ps1 -UseWinbIndex -KBNumber 'KB5068861' -TargetBinaries @('tcpip.sys')"
Move-Item .\binaries\tcpip.sys .\tcpip-patched.sys

# IMPORTANT: Always verify the versions match what you expected!
(Get-Item .\tcpip-vulnerable.sys).VersionInfo.FileVersion
# Expected: 10.0.26100.6899 (check this matches the KB's documented version)
(Get-Item .\tcpip-patched.sys).VersionInfo.FileVersion
# Expected: 10.0.26100.7019 (check this matches the KB's documented version)

# If versions don't match, the script will rename files with .WRONG_VERSION_ suffix
# In that case, use MSU extraction or copy from a patched system

ghidriff .\tcpip-vulnerable.sys .\tcpip-patched.sys -o tcpip_diff
```

**Handling Delta/Differential Updates**:

Some Windows updates (especially recent cumulative updates like KB5070312 and KB5068861) use Forward Differential compression. These updates contain:

```
extract/
├── Windows11.0-KB5068861-x64.psf    # Delta patches (1.1GB) - NOT directly extractable
├── Windows11.0-KB5068861-x64.wim    # Metadata only (.cat, .mum, .xml files)
├── SSU-26100.7010-x64.cab           # Servicing Stack Update (~19MB)
├── DesktopDeployment.cab            # Deployment tools (~11MB)
├── *.msix.rif.cab                   # MSIX metadata (~11KB each, 50+ files)
├── *.msix                           # App packages (no system binaries)
└── wsusscan.cab                     # WSUS metadata
```

**Understanding the WIM+PSF Format (Windows 11 24H2+)**:

This newer update format is fundamentally different from older Windows updates:

| Component        | Contents                                | Can Extract Binaries?                 |
| ---------------- | --------------------------------------- | ------------------------------------- |
| `.psf` file      | Binary delta patches (differences only) | No - requires base files              |
| `.wim` file      | Manifests, catalogs, metadata           | No - no binaries inside               |
| `SSU-*.cab`      | Servicing Stack Update binaries         | SSU files only                        |
| `*.msix` files   | UWP app packages                        | App binaries only (not kernel/system) |
| `*.msix.rif.cab` | MSIX metadata                           | No - just XML/catalogs                |

### Finding the Right Binary Versions

**Using WinbIndex**:

1. Visit [Winbindex](https://winbindex.m417z.com/)
2. Search for binary name (e.g., `ntdll.dll`, `tcpip.sys`)
3. View version history with KB numbers
4. Download specific versions directly

**Example - Finding ntdll.dll Versions**:

```
# Search: ntdll.dll
# Results show:
# Windows                Update      File arch   File version
# Windows 11 24H2 (+1)	 KB5068861   x86         10.0.26100.7171
# Windows 10 1809     	 KB5068791   x64         10.0.17763.8024
# Windows 10 21H2 (+1)   KB5068781   x86         10.0.19041.6575
# Windows 11 24H2 (+1)	 KB5068861   x64         10.0.26100.7019
```

**Identifying Changed Files**:

- MSRC security bulletins list affected binaries
- GitHub security advisories often specify components
- CVE descriptions may mention specific DLLs/drivers

### Symbol Files and PDB

**Why Symbols Matter**:

- Function names make analysis infinitely easier
- Variable names provide context
- Structure definitions reveal data layouts
- Simplified debugging and correlation

**Downloading Symbols**:

```bash
# Using Microsoft Symbol Server
# Requires Debugging Tools for Windows
# download and install from https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/

$symbolPath = "C:\Symbols"
New-Item -ItemType Directory -Force -Path $symbolPath

# Configure symbol path
$env:_NT_SYMBOL_PATH = "SRV*$symbolPath*https://msdl.microsoft.com/download/symbols"

# Use symchk to download symbols for binaries
$env:Path += ";C:\Program Files (x86)\Windows Kits\10\Debuggers\x64"
symchk /r C:\patch-analysis\binaries /s SRV*$symbolPath*https://msdl.microsoft.com/download/symbols
```

### Practical Exercise

**Task**: Extract and prepare two consecutive Windows 11 updates for diffing

0. **Example Analysis**:

- [CVE-2025-59287](https://code-white.com/blog/wsus-cve-2025-59287-analysis/)
- [CVE-2024-20696](https://clearbluejar.github.io/posts/patch-tuesday-diffing-cve-2024-20696-windows-libarchive-rce/)

1. **Identify Target**:
   - Choose a recent security update (check [MSRC Security Update Guide](https://msrc.microsoft.com/update-guide/))
   - Find the KB number and affected binaries
   - Example targets:
     - CVE-2025-60720: for example you need to download tdx.sys KB5067036 as the vulnerable version and KB5068861 for the patched version
     - CVE-2025-60707: mmcss.sys patched at KB5068861, find the vulnerable version
     - CVE-2025-59255: figure out binary, patched at KB5066835, vulnerable version at KB5065789
     - CVE-2025-59192: find vulnerable binary and patched, vulnerable versions
     - CVE-2025-55224: find vulnerable binary and patched, vulnerable versions
     - CVE-2025-62452: find vulnerable binary and patched, vulnerable versions

2. **Download Updates**:
   - find the file that you need to download
   - and vulnerable and patched kb versions

3. **Extract Binaries**:

   ```bash
   cd c:\patch-analysis
   powershell -ExecutionPolicy Bypass -Command ".\Extract-Patch.ps1 -UseWinbIndex -KBNumber 'KBXXXXXXX' -TargetBinaries @('x.y')"
   mkdir vulnerable
   mv binaries/x.y vulnerable
   powershell -ExecutionPolicy Bypass -Command ".\Extract-Patch.ps1 -UseWinbIndex -KBNumber 'KBXXXYYYY' -TargetBinaries @('x.y')"
   mkdir patched
   mv binaries/x.y patched

   # in either cases get the symbols required
   & 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /r C:\patch-analysis\vulnerable /s SRV*C:\patch-analysis\vulnerable*https://msdl.microsoft.com/download/symbols
   & 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /r C:\patch-analysis\patched /s SRV*C:\patch-analysis\patched*https://msdl.microsoft.com/download/symbols
   ```

4. **Organize Files**:

   ```
   patch-analysis/
   ├── vulnerable/
   │   ├── x.y (version 10.0.2xxxx.xxxx)
   │   └── x.y.pdb
   ├── patched/
   │   ├── x.y (version 10.0.2yyyy.yyyy)
   │   └── x.y.pdb
   ```

**Success Criteria**:

- Both binary versions extracted
- File sizes confirmed different
- Symbols downloaded successfully
- Directory structure organized for next steps

### Key Takeaways

1. **Patch diffing reveals vulnerabilities**: The patch is often the only source of truth
2. **Extraction is multi-layered**: .msu → .cab → .cab → binaries
3. **Symbols are essential**: Makes diffing practical and interpretable
4. **Organization matters**: Clean directory structure prevents confusion
5. **Automation saves time**: Scripts for extraction and symbol download are invaluable

### Discussion Questions

1. Why might vendors release patches without detailed CVE write-ups?
2. What are the ethical considerations of patch diffing before a patch is widely deployed?
3. How do delta patches complicate the extraction process?
4. What strategies can vendors use to make patch diffing harder for attackers?

## Day 2: Binary Diffing Tools (BinDiff and Ghidriff)

- **Goal**: Learn to use industry-standard diffing tools to compare patched binaries.
- **Activities**:
  - _Reading_:
    - [BinDiff Manual](https://www.zynamics.com/bindiff/manual/)
    - [Ghidriff Documentation](https://github.com/clearbluejar/ghidriff)
  - _Online Resources_:
    - [IDA Pro Documentation](https://docs.hex-rays.com/)
    - [Ghidra Documentation](https://ghidra-sre.org/)
    - [ghidriff Walkthrough](https://www.youtube.com/watch?v=nOrDIv34Zcw)
  - _Tool Setup_:
    - Install IDA Pro + BinDiff 8
    - OR install Ghidra 11.4+ + Ghidriff
  - _Exercise_:
    - Perform first diff on yesterday's extracted binaries
    - Identify changed functions

### Tool Choice: IDA + Diaphora vs Ghidra + Ghidriff

**IDA Pro + Diaphora**:

- **Pros**:
  - Industry standard IDA with excellent decompilation
  - Diaphora is free, open-source, and actively maintained
  - Unique features: microcode diffing, vulnerability detection, pseudo-code patches
  - Rich ecosystem of IDA plugins and scripts
- **Cons**:
  - IDA Pro is expensive ($1,000+ for personal license)
  - IDA Free has limitations (no Hex-Rays decompiler)
  - Diaphora uses AGPL license (affects commercial use)
- **Best For**: Professional vulnerability researchers with IDA licenses

**IDA Pro + BinDiff 8** (Legacy):

- **Status**: BinDiff 8 only supports IDA 8.0-8.3, NOT IDA 9.x
- **Alternative**: Build from source with newer IDA SDK (requires effort)

**Ghidra + Ghidriff**:

- **Pros**:
  - Completely free and open-source (Ghidra and Ghidriff)
  - Excellent multi-architecture support
  - Built-in version tracking tool in Ghidra
  - Ghidriff automates diffing with markdown/JSON reports
  - Headless analysis perfect for CI/CD pipelines
  - Docker support for reproducible analysis
- **Cons**:
  - Decompiler slightly less polished than Hex-Rays
  - Steeper learning curve for GUI
  - Fewer third-party plugins than IDA ecosystem
- **Best For**: Budget-conscious researchers, automation needs, open-source preference

**This Course**: Primary focus on **Ghidra + Ghidriff** for accessibility. Diaphora workflows covered for those with IDA access.

### Installing IDA + BinDiff

**Option 1: Use IDA Pro 8.x with BinDiff 8**

```bash
# Download BinDiff 8 from https://github.com/google/bindiff/releases
# Note: Last release is from 2023, supports IDA 8.0-8.3

# Windows Installation:
# 1. Install IDA Pro 8.x to C:\Program Files\IDA Professional 8.x
# 2. Install BinDiff 8 (automatically detects IDA)
# 3. Launch IDA, verify BinDiff plugin loaded:
#    Edit → Plugins → BinDiff should appear
```

**Option 2: Use Diaphora with IDA Pro 8.x**

[Diaphora](https://github.com/joxeankoret/diaphora) is an excellent open-source alternative. Per its README, it supports IDA 7.4+ and requires Python 3.x (tested up to Python 3.11). The README mentions IDA 6.8 to 8.4.

```bash
# Clone Diaphora
# if on windows, install git then
git clone --depth 1 https://github.com/joxeankoret/diaphora.git

# Option A: Run directly from IDA
# File → Script file → select diaphora.py

# Option B: Install as plugin
# Copy plugins/diaphora_plugin.py and plugins/diaphora_plugin.cfg to IDA's plugins directory
# Edit diaphora_plugin.cfg and set the path to your Diaphora directory
```

**Option 3: Build BinDiff from Source** (Advanced)

BinDiff is now open-source and can be built with IDA SDK support:

```bash
# Clone repositories
git clone https://github.com/google/bindiff.git
git clone https://github.com/google/binexport.git

# Build requires:
# - IDA SDK 8.2+ (unpack into deps/idasdk)
# - CMake 3.14+, Ninja, GCC 9+ or Clang
# See: https://github.com/google/bindiff#building-from-source

# Note: Building with IDA 9.x SDK may require patches to BinExport
# Check issues on both repos for IDA 9.x compatibility updates
```

**Option 4: Use Ghidra + Ghidriff** (Recommended)

This is the recommended approach for this course - see next section.

### Installing Ghidra + Ghidriff

```bash
$toolsDir = "$env:USERPROFILE\tools"
if (-not (Test-Path $toolsDir)) { New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null }
Set-Location $toolsDir
Invoke-WebRequest -Uri "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.4.2_build/ghidra_11.4.2_PUBLIC_20250826.zip" -OutFile "ghidra_11.4.2_PUBLIC_20250826.zip"
Expand-Archive -Path "ghidra_11.4.2_PUBLIC_20250826.zip" -DestinationPath "." -Force
$ghidraDir = "$toolsDir\ghidra_11.4.2_PUBLIC"
$env:GHIDRA_INSTALL_DIR = $ghidraDir
[Environment]::SetEnvironmentVariable("GHIDRA_INSTALL_DIR", $ghidraDir, "User")
Set-Location $ghidraDir
winget install Microsoft.OpenJDK.17
$jdkPath = (Get-ChildItem "C:\Program Files\Microsoft" -Directory | Where-Object { $_.Name -like "jdk-17*" } | Select-Object -First 1).FullName
$env:JAVA_HOME = $jdkPath
[Environment]::SetEnvironmentVariable("JAVA_HOME", $jdkPath, "User")
.\ghidraRun.bat
winget install Python.Python.3.11
& "$env:USERPROFILE\AppData\Local\Programs\Python\Python311\Scripts\pip" install "jpype1==1.5.2cd"
& "$env:USERPROFILE\AppData\Local\Programs\Python\Python311\Scripts\pip" install ghidriff
$pythonScripts = "$env:USERPROFILE\AppData\Local\Programs\Python\Python311\Scripts"
$env:Path += ";$pythonScripts"
$currentUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($currentUserPath -notlike "*$pythonScripts*") {
    [Environment]::SetEnvironmentVariable("Path", "$currentUserPath;$pythonScripts", "User")
}
ghidriff.exe --help
```

**Ghidriff Features**:

Ghidriff has evolved significantly with new capabilities for patch analysis:

> [!NOTE]
> you might need to set java, ghidra and python envs like up there if you haven't

1. **String Reference Diffing**: Track which functions reference which strings - crucial for spotting new error messages, commands, or embedded data:

```bash
ghidriff.exe .\old.sys .\new.sys --output diff_report --strings
```

2. **JSON Export for Automation**: Export structured diff data for CI/CD pipelines:

```bash
ghidriff old.dll new.dll -o results
# Results include: results.json, results.md, results_functions/*.html
```

3. **Docker Support** (Recommended for reproducibility):

```bash
# Pull the official image
docker pull clearbluejar/ghidriff:latest

# Run diff in container
docker run -v $(pwd):/workdir clearbluejar/ghidriff \
    /workdir/old.sys /workdir/new.sys -o /workdir/diff

# With memory limits for large binaries
docker run --memory=8g -v $(pwd):/workdir clearbluejar/ghidriff \
    /workdir/tcpip_old.sys /workdir/tcpip_new.sys \
    -o /workdir/diff --max-section-funcs 5000
```

4. **Debug Logging**: Troubleshoot analysis issues:

```bash
ghidriff --engine-log debug old.sys new.sys -o diff
```

5. **Symbol Integration**: Use PDB symbols for better function names:

```bash
ghidriff old.sys new.sys -o diff --pdb-path ./symbols/
# Ghidriff will automatically match PDBs by name
```

**Handling Large Binaries**:

Large binaries like `ntoskrnl.exe` or `tcpip.sys` can overwhelm default settings:

```bash
# For binaries with 10,000+ functions:
ghidriff old.sys new.sys -o diff \
    --max-section-funcs 10000 \
    --max-ram-percent 80 \
    --engine-log info

# Analyze only .text section (skip .rdata, .data for speed)
ghidriff old.sys new.sys -o diff --section .text

# Skip functions below similarity threshold (focus on changes)
ghidriff old.sys new.sys -o diff --min-func-len 10
```

### Ghidriff Workflow

**Step 1: Basic Diff (Headless)**

```bash
cd c:\patch-analysis
powershell -ExecutionPolicy Bypass -Command ".\Extract-Patch.ps1 -UseWinbIndex -KBNumber 'KB5070773' -TargetBinaries @('tcpip.sys')"
Move-Item .\binaries\tcpip.sys .\old.sys
powershell -ExecutionPolicy Bypass -Command ".\Extract-Patch.ps1 -UseWinbIndex -KBNumber 'KB5068861' -TargetBinaries @('tcpip.sys')"
Move-Item .\binaries\tcpip.sys .\new.sys
$toolsDir = "$env:USERPROFILE\tools"
$ghidraDir = "$toolsDir\ghidra_11.4.2_PUBLIC"
$env:GHIDRA_INSTALL_DIR = $ghidraDir
[Environment]::SetEnvironmentVariable("GHIDRA_INSTALL_DIR", $ghidraDir, "User")
$jdkPath = (Get-ChildItem "C:\Program Files\Microsoft" -Directory | Where-Object { $_.Name -like "jdk-17*" } | Select-Object -First 1).FullName
$env:JAVA_HOME = $jdkPath
[Environment]::SetEnvironmentVariable("JAVA_HOME", $jdkPath, "User")
$pythonScripts = "$env:USERPROFILE\AppData\Local\Programs\Python\Python311\Scripts"
$env:Path += ";$pythonScripts"
$currentUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($currentUserPath -notlike "*$pythonScripts*") {
    [Environment]::SetEnvironmentVariable("Path", "$currentUserPath;$pythonScripts", "User")
}
ghidriff.exe .\old.sys .\new.sys
```

you'll see something like:

```text
# ... lots of text
INFO | ghidriff | Writing pdiff json...
INFO | ghidriff | Writing matches json...
INFO | ghidriff | Wrote ghidriffs\old.sys-new.sys.ghidriff.md (size: 1094K)
INFO | ghidriff | Wrote ghidriffs\json\old.sys-new.sys.ghidriff.json (size: 4533K)
INFO | ghidriff | Wrote ghidriffs\json\old.sys-new.sys.ghidriff.matches.json (size: 2102K)
```

then you can use this pyhton script:

```python
import json

with open(r'ghidriffs\json\old.sys-new.sys.ghidriff.json') as f:
    data = json.load(f)

functions = data.get('functions', {})
added = functions.get('added', [])
deleted = functions.get('deleted', [])
modified = functions.get('modified', [])

print("=== FUNCTION SUMMARY ===")
print(f"  Added:    {len(added)}")
print(f"  Deleted:  {len(deleted)}")
print(f"  Modified: {len(modified)}")

print("\n=== MOST CHANGED FUNCTIONS (top 10) ===")
sorted_modified = sorted(modified, key=lambda x: x.get('ratio', 1.0))

for fc in sorted_modified[:20]:
    old_info = fc.get('old', {})
    new_info = fc.get('new', {})
    name = old_info.get('name') or new_info.get('name') or 'unknown'
    ratio = fc.get('ratio', 1.0)
    print(f"  {name}: {ratio:.0%}")

print("\n=== BIGGEST ADDED FUNCTIONS (top 5) ===")
sorted_added = sorted(added, key=lambda x: x.get('length', 0), reverse=True)

for fc in sorted_added[:5]:
    name = fc.get('name', 'unknown')
    length = fc.get('length', 0)
    print(f"  {name}: {length} bytes")
```

**Step 2: Enhanced Diff with Symbols**

```bash
# If you have PDB symbols (downloaded from Microsoft Symbol Server):
# Symbols should be in: ghidriffs\symbols\tcpip.pdb (for each version)

ghidriff.exe .\old.sys .\new.sys --symbols-path .\ghidriffs\symbols\ --output tcpip_detailed --max-section-funcs 1000 --max-ram-percent 80

# Note: --max-ram-percent limits memory usage (adjust based on system RAM)
# --max-section-funcs limits functions analyzed per section (for large binaries)
# btw you can enhance this way more by adding imported libraries to workflow as well
#Linking the External Programs of 'new.sys' to imported libraries...
#  [NTOSKRNL.EXE] -> not found in project
#  [NETIO.SYS] -> not found in project
#  [NDIS.SYS] -> not found in project
#  [CNG.SYS] -> not found in project
#  [FLTMGR.SYS] -> not found in project
#  [FWPKCLNT.SYS] -> not found in project
#  [HAL.DLL] -> not found in project
#  [KSECDD.SYS] -> not found in project
#  [MSRPC.SYS] -> not found in project
```

**Step 3: Review Markdown Report**

```markdown
# Open .\tcpip_detailed\old.sys-new.sys.ghidriff.md

# you can use https://www.mermditor.dev/editor
```

**Step 4: Examine Function-Level Diffs**

```bash
# open the same markdown in https://www.mermditor.dev/editor
# scroll down and you can see Modified diffs

# for example
# IPSecDoCommonPerPacketInitInboundProcessing
# TcpReceiveSack
# IsNewEdgeIF
# Fl4tMapAddress
# IPSecTraceAndAuditInboundTunnelFilterDrop
# InetInspectReceiveTcpDatagram
```

#### Ghidra Version Tracking (Built-in Alternative)

**Step 0: Preparation**

```bash
cd c:\patch-analysis
powershell -ExecutionPolicy Bypass -Command ".\Extract-Patch.ps1 -UseWinbIndex -KBNumber 'KB5067036' -TargetBinaries @('tdx.sys')"
mkdir vulnerable
mv .\binaries\tdx.sys .\vulnerable\tdx.sys
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /r C:\patch-analysis\vulnerable /s SRV*C:\patch-analysis\vulnerable*https://msdl.microsoft.com/download/symbols
powershell -ExecutionPolicy Bypass -Command ".\Extract-Patch.ps1 -UseWinbIndex -KBNumber 'KB5068861' -TargetBinaries @('tdx.sys')"
mkdir patched
mv .\binaries\tdx.sys .\patched\tdx.sys
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /r C:\patch-analysis\patched /s SRV*C:\patch-analysis\patched*https://msdl.microsoft.com/download/symbols
$toolsDir = "$env:USERPROFILE\tools"
$ghidraDir = "$toolsDir\ghidra_11.4.2_PUBLIC"
Set-Location $ghidraDir
.\ghidraRun.bat
```

**Step 1: Create Ghidra Project**

```bash
# Launch Ghidra
# File → New Project → Non-Shared Project
# Project Directory: c:\patch-analysis\cve-2025-60720
# Project Name: TDXPatchDiff

# Import both binaries:
# File → Import File → c:\patch-analysis\vulnerable\tdx.sys (save as tdx-old.sys or sth)
# File → Import File → c:\patch-analysis\patched\tdx.sys (save as tdx-new.sys or sth)
# Wait for auto-analysis to complete
```

**Step 2: Create Version Tracking Session**

```bash
# Tools → Version Tracking → Create Session
# Name: TDX_Vuln_vs_Patch
# Source Program: tdx-old.sys (vulnerable)
# Destination Program: tdx-new.sys (patched)
# Create session
```

**Step 3: Run Correlators**

```bash
# Inside Version Tracking click on the magic wand
# Auto-correlators will run automatically
# Additional correlators to run:
# - Function Name Match Correlator
# - Structural Graph Exact Match
# - Partial Match Correlator (Ghidra 11+)

# Results appear in "Matched Functions" table
# Similarity score indicates how much changed
```

**Step 4: Filter and Analyze**

```bash
# Apply filters:
# - Show Only Unmatched Functions (finds new/deleted)
# - Similarity < 0.9 (finds modified functions)

# For each interesting match:
# - Double-click to open side-by-side comparison
# - Review decompiled code differences
# - Note security-relevant changes
```

**Step 5: Cheat Code**

```bash
# look for FUN_140003be8(older) and FUN_1400129f4(newer name)

# // NEW: Bounds validation before read
#FUN_140010a90(longlong *, local_b0, (undefined8) 0xe00);  // Validate size ≤ 0xe00?

#// NEW: Compare memory to ensure bounds
#pVar3 = RtlCompareMemory(...);
#if (pVar3 != expected || ...) {
#    goto LAB_140012c5a;  // Bail out - invalid access
#}

#// NEW: Additional pointer/offset validation
#if ((iVar3 == 0) || (*(int *)(iVar2 + 0x20) == 0) || ...) {
#    // Reject invalid input
#}
```

### BinDiff Workflow (IDA Pro)

**Step 1: Create Project and Load Binaries**

```bash
# Launch IDA Pro
# File → Open → Select vulnerable\win32k.sys
# Auto-analysis will run (may take 5-15 minutes)
# File → Produce file → Create BinExport file (.BinExport)
# Save as: win32k_vulnerable.BinExport

# Repeat for patched version:
# File → Open → Select patched\win32k.sys
# Create BinExport: win32k_patched.BinExport
```

**Step 2: Run BinDiff**

```bash
# In IDA Pro with either database open:
# Edit → Plugins → BinDiff → Diff Database

# Select:
# Primary: win32k_vulnerable.BinExport
# Secondary: win32k_patched.BinExport

# BinDiff Analysis Window opens showing:
# - Statistics (matched functions, changed functions, new/deleted)
# - Matched functions list with similarity scores
# - Call graph comparison
```

**Step 3: Analyze Results**

```bash
# Sort functions by Similarity (ascending)
# Focus on functions with < 0.95 similarity

# Look for:
# - Added validation checks (if statements)
# - New function calls (input sanitization)
# - Changed buffer size calculations
# - Modified bounds checks
```

**Step 4: Visual Diff**

```bash
# Double-click a function with low similarity
# BinDiff opens side-by-side view:
#   Left: Vulnerable function
#   Right: Patched function
#
# Red blocks: Deleted in patch
# Green blocks: Added in patch
# Yellow blocks: Modified logic
#
# Focus on green blocks - usually the fix
```

### Diaphora Workflow (IDA Pro)

**Step 1: Export Databases**

```bash
# Launch IDA Pro and open the vulnerable binary
# File → Open → Select vulnerable\win32k.sys
# Wait for auto-analysis to complete

# Run Diaphora to export database
# File → Script file → select diaphora.py
# Or use plugin: Edit → Plugins → Diaphora (if installed)

# In Diaphora dialog:
# - Output database: win32k_vulnerable.sqlite
# - Click "Export"
# Wait for export to complete (progress shown in Output window)

# Repeat for patched version:
# File → Open → Select patched\win32k.sys
# Run Diaphora, export to: win32k_patched.sqlite
```

**Step 2: Run Diff**

```bash
# With the patched database open in IDA:
# File → Script file → diaphora.py

# In Diaphora dialog:
# - Select "Diff against..." tab
# - Choose: win32k_vulnerable.sqlite
# - Configure options:
#   - Enable "Use decompiler" (if Hex-Rays available)
#   - Enable "Diffing pseudo-code"
#   - Enable "Relaxed ratio calculations" for large binaries
# - Click "Diff"

# Diff results appear in multiple tabs:
# - Best matches (100% similarity)
# - Partial matches (< 100% similarity) ← Focus here!
# - Unmatched functions
```

**Step 3: Analyze Partial Matches**

```bash
# In "Partial matches" tab:
# - Sort by "Ratio" column (ascending)
# - Functions with ratio < 0.95 likely contain security fixes

# Double-click a function to see side-by-side comparison:
# - Left pane: Vulnerable version
# - Right pane: Patched version
# - Differences highlighted in color

# Diaphora unique features:
# - Pseudo-code diff (if Hex-Rays available)
# - Assembly diff
# - Microcode diff (IDA 7.5+)
# - Graph-based comparison
```

**Step 4: Use Vulnerability Detection**

Diaphora 3.0+ includes automatic detection of potentially fixed vulnerabilities:

```bash
# After diffing, check the "Potentially fixed vulnerabilities" section
# Diaphora automatically flags:
# - Added bounds checks
# - New NULL pointer validations
# - Integer overflow protections
# - Memory safety improvements

# This feature accelerates finding security-relevant changes
# in large diffs with hundreds of modified functions
```

**Step 5: Port Symbols and Comments**

```bash
# If the vulnerable version has better symbols/comments:
# - Select functions in "Best matches" tab
# - Right-click → "Import all: Names, comments, prototypes"

# This transfers analysis work between versions
# Especially useful when patched version lacks symbols
```

**Diaphora Command-Line Mode** (for automation):

```bash
# Export from command line (IDA batch mode)
ida -A -S"diaphora.py -o:output.sqlite" vulnerable.sys
ida -A -S"diaphora.py -o:output_patched.sqlite" patched.sys

# Diff from command line (without IDA)
python diaphora.py output.sqlite output_patched.sqlite -o diff_results.sqlite

# Results can be viewed in any SQLite browser or imported back into IDA
```

### Filtering Noise: Non-Security Changes

Patches often bundle security fixes with other changes. Learn to filter noise:

**Common False Positives**:

1. **Compiler Version Changes**: Different compiler = different code generation
   - Look for: Changed function prologues/epilogues across ALL functions
   - Solution: Focus on functions with logic changes, not just instruction differences

2. **Code Reorganization**: Functions moved, not changed
   - Look for: Function at different address but identical code
   - Solution: Ghidriff/BinDiff match by content, not address

3. **String/Resource Updates**: Version strings, copyright dates
   - Look for: Changes only in `.rdata` or `.rsrc` sections
   - Solution: Focus on `.text` section changes

4. **Inlined Functions**: Compiler inlined what was previously a call
   - Look for: Function "deleted" but code appears in callers
   - Solution: Check if "deleted" function's code exists elsewhere

5. **Debug Symbol Changes**: Different PDB compilation
   - Look for: Symbol names changed but code identical
   - Solution: Compare actual instructions, not just names

**Tips for Noise Reduction**:

```python
# When reviewing ghidriff output, prioritize:
# 1. Functions with similarity < 0.90 (significant changes)
# 2. Functions with security-relevant names:
security_keywords = [
    'validate', 'check', 'verify', 'sanitize', 'bounds',
    'length', 'size', 'copy', 'parse', 'decode', 'auth',
    'permission', 'access', 'buffer', 'overflow', 'limit'
]

# 3. Functions that handle external input:
input_functions = [
    'recv', 'read', 'input', 'request', 'packet', 'message',
    'header', 'parse', 'decode', 'deserialize', 'unmarshal'
]
```

### Identifying Security-Relevant Changes

**Common Patterns to Look For**:

1. **Added Bounds Checks**:

   ```c
   // BEFORE (vulnerable):
   memcpy(dest, src, user_size);

   // AFTER (patched):
   if (user_size > MAX_SIZE) return ERROR;
   memcpy(dest, src, user_size);
   ```

2. **New Validation Functions**:

   ```c
   // New function added:
   bool ValidateInputBuffer(void* buf, size_t len) {
       if (!buf || len > MAX) return false;
       if (!ProbeForRead(buf, len)) return false;
       return true;
   }
   ```

3. **Changed Size Calculations**:

   ```c
   // BEFORE:
   size = width * height;  // Integer overflow!

   // AFTER:
   if (!SafeMultiply(width, height, &size)) return ERROR;
   ```

4. **Additional NULL Checks**:

   ```c
   // BEFORE:
   ptr->field = value;  // Crash if ptr is NULL

   // AFTER:
   if (!ptr) return ERROR;
   ptr->field = value;
   ```

5. **Initialization Changes**:

   ```c
   // BEFORE:
   HANDLE handle;  // Uninitialized

   // AFTER:
   HANDLE handle = NULL;  // Properly initialized
   ```

6. **Error Handling Changes**:
   - New `try/catch` or `__try/__except` blocks
   - Changed return value checks
   - Added cleanup paths

7. **Cryptographic Updates**:
   - Algorithm changes (MD5 → SHA256)
   - Key length modifications
   - Random number generator updates

8. **Access Control Modifications**:
   - New permission checks
   - Changed ACL handling
   - Token validation additions

9. **Memory Management**:
   - Changed allocator (malloc → calloc)
   - Added memory zeroing before free
   - Buffer size recalculations

### Practical Exercise

**Task**: Diff a couple of the cases you've chosen from day 1 and identify security changes

1. **Run BinDiff or Ghidriff**:
   - Compare vulnerable vs patched binaries
   - Generate similarity report

2. **Identify Top 5 Most-Changed Functions**:
   - Sort by similarity score (ascending)
   - List function names and addresses

3. **Analyze Each Function**:
   - What code was added?
   - What code was removed?
   - What appears to be the bug?

4. **Categorize the Fix**:
   - Bounds check?
   - NULL pointer check?
   - Integer overflow fix?
   - Logic error correction?

5. **Document Findings**:

   ```markdown
   ## Function: NtUserGetWindowBand

   - **Similarity**: 0.87
   - **Change Type**: Added bounds check
   - **Details**: New validation ensures band_index < MAX_BANDS
   - **Likely Bug**: Out-of-bounds array access
   - **Exploitability**: Potential info leak or memory corruption
   ```

**Success Criteria**:

- Successfully completed diff with either tool
- Identified at least 3 changed functions
- Recognized common security fix patterns
- Documented findings in structured format

### Key Takeaways

1. **Tools automate comparison**: But human analysis finds the meaning
2. **Multiple tools available**: Choose based on budget and preferences
3. **Similarity score guides focus**: Lower score = more significant changes
4. **Patterns are recognizable**: After analyzing several patches, fixes become obvious
5. **Documentation is crucial**: Clear notes enable exploitation phase

### Discussion Questions

1. What are the advantages of automated diffing tools over manual comparison?
2. How can false positives (non-security changes) be filtered out efficiently?
3. Why might a function show low similarity despite no security fix?
4. What additional analysis techniques can supplement binary diffing?

## Day 3: Case Study - CVE-2022-34718 (EvilESP)

- **Goal**: Walk through a complete patch diff analysis of a Windows TCP/IP vulnerability.
- **Activities**:
  - _Reading_:
    - [MSRC CVE-2022-34718](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-34718) - Official Microsoft advisory
    - RFC 4303: [IP Encapsulating Security Payload (ESP)](https://datatracker.ietf.org/doc/html/rfc4303)
    - RFC 8200: [IPv6 Specification](https://www.rfc-editor.org/rfc/rfc8200.html)
    - [PoC for CVE-2022-34718](https://github.com/SecLabResearchBV/CVE-2022-34718-PoC)
  - _Concepts_:
    - ESP packet structure
    - IPv6 fragmentation and reassembly
    - Out-of-bounds write exploitation
    - Binary diffing workflow

### Vulnerability Overview

From Week 1, you briefly classified CVE-2022-34718 (EvilESP) as an out-of-bounds write in `tcpip.sys`. Here you will dig into the actual patch and see exactly how Microsoft fixed that bug.

**CVE-2022-34718**:

- **Component**: `tcpip.sys` (Windows TCP/IP stack)
- **Type**: Out-of-bounds 1-byte write
- **Impact**: Remote Code Execution (RCE)
- **CVSS**: 9.8 (Critical)
- **Affected**: Windows Server 2022, Windows 11, Windows 10 (with IPsec enabled)
- **Patch Date**: September 2022
- **Discoverer**: MDSec

**Attack Scenario**:
Unauthenticated attacker sends specially crafted IPv6 packets encapsulated in ESP (IPsec) to trigger out-of-bounds write in kernel memory, leading to RCE with SYSTEM privileges.

### Patch Diffing Process

**Step 1: Binary Acquisition**

```bash
# Use WinbIndex (https://winbindex.m417z.com/) to get tcpip.sys versions:
# - Vulnerable: 10.0.22621.521 (August 2022, KB5019311)
# - Patched:    10.0.22621.608 (September 2022, KB5017389)
cd c:\patch-analysis
powershell -ExecutionPolicy Bypass -Command ".\Extract-Patch.ps1 -UseWinbIndex -KBNumber 'KB5019311' -TargetBinaries @('tcpip.sys')"
mkdir vulnerable
mv .\binaries\tcpip.sys .\vulnerable\tcpip.sys
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /r C:\patch-analysis\vulnerable /s SRV*C:\patch-analysis\vulnerable*https://msdl.microsoft.com/download/symbols
powershell -ExecutionPolicy Bypass -Command ".\Extract-Patch.ps1 -UseWinbIndex -KBNumber 'KB5017389' -TargetBinaries @('tcpip.sys')"
mkdir patched
mv .\binaries\tcpip.sys .\patched\tcpip.sys
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /r C:\patch-analysis\patched /s SRV*C:\patch-analysis\patched*https://msdl.microsoft.com/download/symbols
# as you'll see because of msdl collision this gets you the wrong version with zero changed files
# download tcpip.sys version 10.0.22621.382	from winbindex instead and rename and move it
mkdir old
cp FDD285223F1BE030C131F726D0A8B5AA057BD1D72CFA8CDF96FA8523F531A5BF00.blob old/tcpip.sys
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /r C:\patch-analysis\old /s SRV*C:\patch-analysis\old*https://msdl.microsoft.com/download/symbols
```

**Step 2 Option 1: Load in Ghidra and use version tracking**

```bash
$toolsDir = "$env:USERPROFILE\tools"
$ghidraDir = "$toolsDir\ghidra_11.4.2_PUBLIC"
Set-Location $ghidraDir
.\ghidraRun.bat
# Create Ghidra project: EvilESP_Analysis
# File → New Project → Non-Shared Project
# Project Name: EvilESP_Analysis
# Project Directory: C:\patch-analysis\cve-2022-34718

# Import both tcpip.sys versions:
# File → Import File → old/tcpip.sys
# File → Import File → vulnerable/tcpip.sys
# Wait for auto-analysis to complete

# Tools → Version Tracking → Create Session
# Source: tcpip.sys (vulnerable)
# Destination: tcpip.sys (patched)

# Run correlators:
# - Function Name Match Correlator
# - Structural Graph Exact Match
# Result:
# - IppReceiveEsp: 98.7% similar
# - Ipv6pReassembleDatagram: 99.1% similar
```

**Step 2 Opion 2: Run Binary Diff**

```bash
# Run ghidriff from command line
New-Item -ItemType Directory -Force -Path "symbols\tcpip.pdb"

Copy-Item -Recurse ".\patched\tcpip.pdb\811699FF6B46796C9C6788C5DA2735941" ".\symbols\tcpip.pdb\"
Copy-Item -Recurse ".\vulnerable\tcpip.pdb\AB9499ECCA01FC4D74D17312A46ECB601" ".\symbols\tcpip.pdb\"

ghidriff.exe .\vulnerable\tcpip.sys .\patched\tcpip.sys `
    --output tcpip_evilesp_diff `
    --symbols-path .\symbols `
    --max-section-funcs 5000 `
    --max-ram-percent 80
# open tcpip_evilesp_diff\tcpip.sys-tcpip.sys.ghidriff.md in https://www.mermditor.dev/editor

Copy-Item -Recurse ".\old\tcpip.pdb\58E31A1BDDBE1E92FF271C43B8D6250A1" ".\symbols\tcpip.pdb\"

ghidriff.exe .\old\tcpip.sys .\patched\tcpip.sys `
    --output evilesp_diff `
    --symbols-path .\symbols `
    --max-section-funcs 5000 `
    --max-ram-percent 80

# open evilesp_diff\tcpip.sys-tcpip.sys.ghidriff.md in https://www.mermditor.dev/editor
```

#### Function 1: IppReceiveEsp

**Vulnerable Code**

```c
void IppReceiveEsp(longlong *param_1)
{

    piVar1 = (int *)param_1[1];
    puVar2 = *(undefined8 **)(param_1[0x18] + 0x28);

    // Check if buffer size < 8 bytes (minimum ESP header)
    if (*(uint *)(*(longlong *)(piVar1 + 2) + 0x18) < 8) {
        puVar3 = IppDiscardReceivedPackets((longlong)puVar2, 5, param_1, 0, 0, 0, 0xe0004131);
        if ((int)puVar3 == 0) {
            IppSendErrorListForDiscardReason(0, puVar2, param_1, 5, 0);
        }
        if (param_1[1] != 0) {
            *(undefined4 *)(param_1[1] + 0x8c) = 0xc000021b;
        }
    }
    else {
        // Process ESP packet
        IppReceiveEspNbl(piVar1, *(short *)(puVar2 + 0x1c), (int *)(puVar2 + 0x18),
                         (uint *)param_1[0x20], (uint *)param_1[0x1e],
                         (longlong *)(param_1[0x1b] + 0x10),
                         (uint *)((longlong)param_1 + 0x30),
                         (int *)((longlong)param_1 + 0x2c));

        // VULNERABLE: Only checks for success (0) or pending (0x105)
        // No validation of the result code range
        if (piVar1[0x23] == 0) {
            return;
        }
        if (piVar1[0x23] == 0x105) {
            return;
        }
    }
    *(undefined4 *)((longlong)param_1 + 0x2c) = 0x3b;
    return;
}
```

**Patched Code**

```c
void IppReceiveEsp(longlong *param_1)
{
    piVar2 = (int *)param_1[1];
    puVar3 = *(undefined8 **)(param_1[0x18] + 0x28);

    if (*(uint *)(*(longlong *)(piVar2 + 2) + 0x18) < 8) {
        puVar4 = IppDiscardReceivedPackets((longlong)puVar3, 5, param_1, 0, 0, 0, 0xe0004131);
        IppSendErrorListForDiscardReason(0, puVar3, param_1, 5, 0);
        if (param_1[1] != 0) {
            *(undefined4 *)(param_1[1] + 0x8c) = 0xc000021b;
        }
    }
    else {
        IppReceiveEspNbl(piVar2, *(short *)(puVar3 + 0x1c), (int *)(puVar3 + 0x18),
                         (uint *)param_1[0x20], (uint *)param_1[0x1e],
                         (longlong *)(param_1[0x1b] + 0x10),
                         (uint *)((longlong)param_1 + 0x30),
                         (int *)((longlong)param_1 + 0x11a),  // NEW: Additional parameter
                         (int *)((longlong)param_1 + 0x2c));

        if ((piVar2[0x23] == 0) || (piVar2[0x23] == 0x105)) {
            // PATCH: Added validation of result code at offset 0x2c
            iVar3 = *(int *)((longlong)param_1 + 0x2c);
            if ((iVar3 != 0) && (1 < (uint)(iVar3 - 0x2b))) {
                // Valid result in range [0x2c, 0x3a] - safe to return
                return;
            }
            // Invalid result - discard and set error
            IppDiscardReceivedPackets((longlong)puVar3, 6, param_1, 0, 0, 0, 0xe0004148);
            *(undefined4 *)(piVar2 + 0x8c) = 0xc000021b;
        }
    }
    *(undefined4 *)((longlong)param_1 + 0x2c) = 0x3b;
    return;
}
```

#### Function 2: Ipv6pReassembleDatagram

**Vulnerable Code**

```c
void Ipv6pReassembleDatagram(undefined8 param_1, longlong param_2, undefined1 param_3)
{
    // Calculate sizes
    uVar11 = *(int *)(param_2 + 0x8c) + (uint)*(ushort *)(param_2 + 0x88);
    uVar4 = *(ushort *)(param_2 + 0x88) + 0x28;
    plVar6 = *(longlong **)(*(longlong *)(param_1 + 0xd0) + 8);
    lVar8 = *(longlong *)(*plVar6 + 0x28);

    // ... setup code ...

    // VULNERABLE: Only checks uVar1 < uVar13, missing upper bound check
    if (uVar1 < uVar13) {
        // Process reassembly without proper size validation
        IppRemoveFromReassemblySet(lVar8 + 0x4f00, param_2, param_3);

        for (puVar5 = *(undefined8 **)(param_2 + 0x60); puVar5 != NULL; puVar5 = *puVar5) {
            NetioExpandNetBuffer(lVar4, puVar5 + 2, *(undefined4 *)(puVar5 + 7));
        }

        // VULNERABLE: No validation before memory operations
        uVar10 = in_stack_FFFFFFFFFFFFFF & 0xffffffff;
        uVar5 = 0;
        lVar3 = NetioAllocateAndReferenceNetBufferAndNetBuffer(
                    IppReassemblyNetBufferListComplete, param_2, 0, 0, uVar10);

        if (lVar3 == 0) {
            IppDeleteFromReassemblySet(lVar8 + 0x4f00, param_2, param_3);
        }
        else {
            // Process without checking if size could overflow
            lVar4 = *(longlong *)(lVar3 + 8);
            uVar5 = 0;
            uVar10 = NetioRetreatNetBuffer(lVar4, uVar5);

            if (-1 < (int)uVar10) {
                uVar15 = 0;
                puVar5 = (undefined *)NdisGetDataBuffer(lVar4, uVar11, uVar15, 1, 0);
                IppCopyPacket(param_1, uVar11, puVar5);

                // ... copy operations without bounds validation ...

                memcpy(puVar5 + 5, *(void **)(param_2 + 0x80),
                       (ulonglong)*(ushort *)(param_2 + 0x88));
            }
        }
    }
    // ...
}
```

**Patched Code**

```c
void Ipv6pReassembleDatagram(undefined8 param_1, longlong param_2, undefined1 param_3)
{
    // Calculate sizes
    uVar11 = *(int *)(param_2 + 0x8c) + (uint)*(ushort *)(param_2 + 0x88);
    uVar4 = *(ushort *)(param_2 + 0x88) + 0x28;
    plVar6 = *(longlong **)(*(longlong *)(param_1 + 0xd0) + 8);
    lVar8 = *(longlong *)(*plVar6 + 0x28);

    // PATCH 1: Check for 16-bit overflow (IPv6 payload length field is 16-bit)
    if (uVar14 < 0x10001) {
        // PATCH 2: Validate nextheader_offset against header buffer size
        if (*(ushort *)(param_2 + 0xbc) <= uVar13) {
            uVar15 = is_shim_FFFFFFFFFFFFFF & 0xffffffff00;
            uVar5 = 0;
            lVar3 = NetioAllocateAndReferenceNetBufferAndNetBufferList(
                        IppReassemblyNetBufferListsComplete, param_2, 0, 0, 0, uVar15);

            if (lVar3 == 0) {
                IppDeleteFromReassemblySet(lVar8 + 0x4f00, param_2, param_3);
            }
            else {
                lVar4 = *(longlong *)(lVar3 + 8);
                iVar5 = NetioRetreatNetBuffer(lVar4, uVar13, 0);

                if (-1 < iVar5) {
                    puVar7 = (undefined8 *)NdisGetDataBuffer(lVar4, uVar13, 0, 1, 0);
                    lVar9 = IppCopyPacket(param_1);

                    if (lVar9 != 0) {
                        // ... safe copy operations ...

                        memcpy(puVar7 + 5, *(void **)(param_2 + 0x80),
                               (ulonglong)*(ushort *)(param_2 + 0x88));

                        // ... header processing ...

                        IppRemoveFromReassemblySet(lVar8 + 0x4f00, param_2, param_3);

                        for (puVar7 = *(undefined8 **)(param_2 + 0x60);
                             puVar7 != NULL; puVar7 = (undefined8 *)*puVar7) {
                            NetioExpandNetBuffer(lVar4, puVar7 + 2, *(undefined4 *)(puVar7 + 7));
                        }

                        // PATCH 3: Validate final reassembled size
                        if (uVar14 + 0x28 < *(uint *)(lVar4 + 0x18)) {
                            // Size mismatch - log failure
                            if ((DAT_1c0222618 & 0x20) != 0) {
                                McTemplateK0qq_EtwWriteTransfer(
                                    &MICROSOFT_TCPIP_PROVIDER_Context,
                                    &TCPIP_IP_REASSEMBLY_FAILURE_PKT_LEN,
                                    &MICROSOFT_TCPIP_PROVIDER, (int)plVar6[1]);
                            }
                        }
                        else {
                            // Continue with safe processing
                            // ... IPsec validation, work item queuing ...
                        }

                        IppCompleteAndFreePacketList(lVar9, 0);
                        goto LAB_cleanup;
                    }
                }
                IppRemoveFromReassemblySet(lVar8 + 0x4f00, param_2, param_3);
                NetioDereferenceNetBufferList(lVar3, 0);
            }

LAB_memory_fail:
            if (DAT_1c0222614 < 0) {
                McTemplateK0z_EtwWriteTransfer(
                    &MICROSOFT_TCPIP_PROVIDER_Context, &TCPIP_MEMORY_FAILURES);
            }
            goto LAB_cleanup;
        }
    }
    else {
        // PATCH 4: Log packet length overflow
        if ((DAT_1c0222618 & 0x20) != 0) {
            McTemplateK0qq_EtwWriteTransfer(
                &MICROSOFT_TCPIP_PROVIDER_Context,
                &TCPIP_IP_REASSEMBLY_FAILURE_PKT_LEN,
                &MICROSOFT_TCPIP_PROVIDER, (int)plVar6[1]);
        }
   :}

    // Cleanup path for invalid packets
    IppDeleteFromReassemblySet(lVar8 + 0x4f00, param_2, param_3);

LAB_cleanup:
    // Increment failure counters
    piVar1 = (int *)(lVar3 + 8);
    *piVar1 = *piVar1 + 1;
    piVar1 = (int *)(lVar12 + 0x8c);
    *piVar1 = *piVar1 + 1;
    return;
}
```

#### Root Cause Analysis

**Understanding the Vulnerability Context**:

This vulnerability exists in the IPv6 fragment reassembly path when processing ESP (Encapsulating Security Payload) packets.

**ESP Packet Structure** (RFC 4303):

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Security Parameters Index (SPI)           [4 bytes]           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Sequence Number                           [4 bytes]           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Payload Data           [variable]          |
~                                                               ~
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Padding (0-255 bytes)                 | Pad Length | NH   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                              [1 byte]   [1 byte]
```

**IPv6 Fragment Header**:

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Next Header   | Reserved      | Fragment Offset       |Res|M|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Identification                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**The Bug** (Two-Part Vulnerability):

**Part 1 - IppReceiveEsp (Missing Result Validation):**

```
1. Attacker sends crafted ESP packet via IPv6
2. IppReceiveEspNbl processes packet, returns result in param_1[0x2c]
3. Vulnerable code only checks for 0 (success) or 0x105 (pending)
4. Malformed packet causes unexpected result code
5. Code continues execution with invalid state
6. Leads to memory corruption in subsequent operations
```

**Part 2 - Ipv6pReassembleDatagram (Integer Overflow + OOB Access):**

```
1. Attacker crafts fragments with malicious size values
2. uVar14 calculation: fragment_data_len + extension_header_len
3. Without check, uVar14 >= 0x10001 causes 16-bit truncation
4. nextheader_offset (param_2 + 0xbc) not validated against buffer
5. memcpy or array access goes out of bounds
6. Result: Kernel memory corruption
```

**Visual Attack Flow**:

```
┌─────────────────────────────────────────────────────────────────┐
│                    ATTACKER (Remote)                            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Craft malicious IPv6 fragments with:                           │
│  - ESP header (IPsec must be enabled on target)                 │
│  - Fragment offsets causing size overflow (>= 0x10001)          │
│  - nextheader_offset pointing beyond buffer                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    VICTIM KERNEL (tcpip.sys)                    │
├─────────────────────────────────────────────────────────────────┤
│  1. Receive IPv6 fragments                                      │
│  2. IppReceiveEsp() - Missing result code validation      BUG 1 │
│     - Continues with invalid state                              │
│  3. Ipv6pReassembleDatagram() - Reassemble fragments            │
│     - No check: uVar14 < 0x10001                          BUG 2 │
│     - No check: nextheader_offset <= buffer_size          BUG 3 │
│  4. memcpy / array write goes OOB                               │
│  5. Kernel memory corruption → RCE or BSOD                      │
└─────────────────────────────────────────────────────────────────┘
```

#### Exploitation Primitive

| Aspect             | Details                                        |
| ------------------ | ---------------------------------------------- |
| **Type**           | Out-of-bounds write (potentially read as well) |
| **Size**           | Variable (controlled via fragment sizes)       |
| **Offset Control** | Via `nextheader_offset` in fragment header     |
| **Trigger**        | Remote, requires IPsec enabled                 |
| **Prerequisite**   | IPv6 enabled (default), IPsec service running  |

#### Exploitation Approach

```
┌─────────────────────────────────────────────────────────────────┐
│  Packet 1:                                                      │
│  [Ether][IPv6 nh=ESP][ESP hdr][Fragment(off=0,M=1)][Routing]... │
│                               └─ Nested inside ESP payload ──┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Packet 2:                                                      │
│  [Ether][IPv6 nh=ESP][ESP hdr][Fragment(off=24,M=0)][Routing]...│
│                               └─ Triggers reassembly ─────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Kernel:                                                        │
│  1. IppReceiveEsp() decrypts/validates ESP                      │
│  2. Extracts nested Fragment headers from payload               │
│  3. Ipv6pReassembleDatagram() processes fragments               │
│  4. Missing bounds check on nested header offsets → OOB         │
└─────────────────────────────────────────────────────────────────┘
```

**Achieving RCE** (Theoretical):

1. **Prerequisite**: Establish IPsec Security Association with target (requires valid SPI + HMAC key)
2. **Heap Grooming**: Send legitimate ESP traffic to create predictable pool state in `NonPagedPoolNx`
3. **Trigger OOB**: Send crafted nested fragment headers inside ESP to corrupt adjacent `NET_BUFFER_LIST` structures
4. **Control Structure Corruption**: Overwrite function pointers or list linkage in adjacent pool allocation
5. **Code Execution**: Redirect execution when corrupted structure is processed

**Challenges**:

- IPsec SA required - must have matching SPI + HMAC authentication key (critical barrier)
- ESP crypto validation must pass before reaching vulnerable code path
- Limited offset control due to extension header field constraints
- Fragment reassembly timeout (~60 seconds) limits attack window
- Windows kernel pool is non-deterministic
- Need to avoid BSOD before achieving stable corruption

#### Patch Summary

| Function                  | Vulnerability                                      | Fix Added                                                              |
| ------------------------- | -------------------------------------------------- | ---------------------------------------------------------------------- |
| `IppReceiveEsp`           | Missing result validation after `IppReceiveEspNbl` | Range check: `(iVar3 != 0) && (1 < (uint)(iVar3 - 0x2b))`              |
| `IppReceiveEsp`           | Continued execution on error                       | Added `IppDiscardReceivedPackets` call with error `0xe0004148`         |
| `Ipv6pReassembleDatagram` | Integer overflow in size (16-bit)                  | Check: `if (uVar14 < 0x10001)`                                         |
| `Ipv6pReassembleDatagram` | OOB via nextheader_offset                          | Check: `if (*(ushort *)(param_2 + 0xbc) <= uVar13)`                    |
| `Ipv6pReassembleDatagram` | Size mismatch                                      | Check: `if (uVar14 + 0x28 < *(uint *)(lVar4 + 0x18))` triggers failure |
| Both                      | No telemetry                                       | Added ETW events: `TCPIP_IP_REASSEMBLY_FAILURE_PKT_LEN`                |

### Lessons Learned

1. **Binary diffing is highly effective**: Only 2 functions changed - instant focus
2. **Protocol knowledge is essential**: Understanding ESP/IPv6 specs was crucial
3. **Simple bugs still exist**: Missing bounds check in complex networking code
4. **Limited primitives are still dangerous**: 1-byte OOB write still got CVE 9.8
5. **Patches reveal exploitation strategies**: Seeing the fix shows how to trigger the bug

### Practical Exercise

**Task**: Apply the EvilESP analysis methodology to a different Windows TCP/IP or network stack vulnerability

**Suggested Targets** (just a suggestion, choose another yourself if you want):

| CVE            | Component                               | Type | Patch Date | Difficulty |
| -------------- | --------------------------------------- | ---- | ---------- | ---------- |
| CVE-2024-38063 | tcpip.sys (IPv6)                        | RCE  | Aug 2024   | Medium     |
| CVE-2021-24086 | tcpip.sys (IPv6 UDP)                    | DoS  | Feb 2021   | Easy       |
| CVE-2021-24074 | tcpip.sys (IPv4 source routing)         | RCE  | Feb 2021   | Medium     |
| CVE-2020-16898 | tcpip.sys (ICMPv6 Router Advertisement) | RCE  | Oct 2020   | Medium     |
| CVE-2024-21407 | Hyper-V (Guest-to-Host)                 | RCE  | Mar 2024   | Hard       |

**Steps**:

1. **Research Your CVE**:
   - Read the MSRC advisory and any public write-ups
   - Identify the affected binary and KB numbers (vulnerable vs patched)
   - Research the relevant protocol (IPv6, ICMPv6, etc.) using RFCs

2. **Acquire Binaries**:
   - Use WinbIndex or Extract-Patch.ps1 to get both versions
   - Download symbols with symchk.exe
   - Verify version numbers match expected builds

3. **Perform Binary Diff**:
   - Run ghidriff or use Ghidra Version Tracking
   - Identify changed functions (expect 1-5 for targeted security patches)
   - Filter out noise (compiler changes, unrelated updates)

4. **Analyze Changed Functions**:
   - What validation was added? (bounds checks, NULL checks, size limits)
   - What was the root cause? (integer overflow, missing check, race condition)
   - Map the vulnerable code path from input to bug

5. **Research the Protocol**:
   - Read the relevant RFC(s) for your vulnerability's protocol
   - Understand packet structures and processing flow
   - Identify what attacker-controlled fields reach the vulnerable code

6. **Write Technical Report**:
   - Follow the Day 6 report template
   - Include decompiled code snippets (before/after)
   - Create an attack flow diagram similar to EvilESP
   - Assess exploitability considering modern mitigations

**Success Criteria**:

- Successfully acquired both binary versions with symbols
- Identified the security-relevant changed functions (not just all changes)
- Located the specific patch additions in decompiled code
- Explained the root cause vulnerability class (OOB, UAF, integer overflow, etc.)
- Documented the protocol-level attack vector with RFC references
- Created attack flow diagram showing: input → processing → vulnerability trigger
- Assessed real-world exploitability (prerequisites, mitigations, reliability)

### Key Takeaways

1. **Binary diffing rapidly focuses analysis**: Only 2 functions changed in tcpip.sys—instant prioritization from 10,000+ functions
2. **Protocol knowledge is essential**: Understanding ESP (RFC 4303) and IPv6 fragmentation (RFC 8200) was crucial to grasp the attack
3. **Simple bugs in complex code are high-impact**: Missing 16-bit overflow check earned CVSS 9.8
4. **Multi-function vulnerabilities are common**: IppReceiveEsp's validation failure enabled Ipv6pReassembleDatagram's OOB write
5. **Prerequisites affect real-world risk**: IPsec SA requirement limits exploitation despite critical rating
6. **Patches reveal trigger conditions**: Seeing the bounds checks shows exactly what inputs cause the bug

### Discussion Questions

1. CVE-2022-34718 requires IPsec SA (valid SPI + HMAC key) yet received CVSS 9.8. How should prerequisites factor into severity ratings?
2. The bug spanned two functions (IppReceiveEsp and Ipv6pReassembleDatagram). How might static analysis or code review catch such cross-function vulnerabilities?
3. IPv6 fragment reassembly is a recurring vulnerability source (CVE-2024-38063, CVE-2021-24086, etc.). What makes reassembly logic error-prone?
4. The patch added ETW telemetry for failed reassembly. How can defenders leverage this, and how might attackers evade detection?

## Day 4: Windows 11 Automated Patch Diffing Pipeline

- **Goal**: Create an automated workflow for monthly Windows patch analysis.
- **Activities**:
  - _Reading_:
    - [Windows Update History](https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information)
    - [Moderately Advanced Ghidra Usage](https://ghidra.re/ghidra_docs/GhidraClass/Advanced/improvingDisassemblyAndDecompilation.pdf)
    - [Patch Diffing + LLMs: ghidriff Featured in OBTS v8](https://www.clearseclabs.com/blog/patch-diffing-llms-ghidriff-obts-2025/)
  - _Online Resources_:
    - [WinbIndex API Documentation](https://m417z.com/Introducing-Winbindex-the-Windows-Binaries-Index/)
    - [PowerShell for Security Researchers](https://powershellexplained.com/)
  - _Tool Setup_:
    - PowerShell 7+
    - Python 3.10+
  - _Exercise_:
    - Build automated patch download → extract → diff pipeline

### Automation

**Why Automate?**:

- Microsoft releases patches monthly (Patch Tuesday - 2nd Tuesday)
- Analyzing every update manually is time-consuming
- Early detection of vulnerabilities provides competitive advantage
- Automation enables continuous monitoring

**Pipeline Stages**:

1. **Monitor**: Detect new security updates
2. **Download**: Fetch updated binaries
3. **Extract**: Unpack .msu/.cab files
4. **Symbol**: Download matching PDB files
5. **Diff**: Compare against previous version
6. **Report**: Generate HTML/PDF summary
7. **Alert**: Notify of high-priority changes

#### PowerShell Automation Script

- You can use the `Extract-Patch.ps1` script from day 1 of this week
- Or as an exercise try to write/find a better script for yourself

#### Python Automation for Ghidriff

**Batch Diffing Script**:

```python
#!/usr/bin/env python3
# ghidriff_batch.py

# Note: ghidriff's CLI and JSON schema can change between versions; if fields
# below don't match your ghidriff output, inspect the JSON and adjust keys.
# This script is designed for ghidriff 0.4.x+ output format.

import subprocess
import json
import os
import glob
from pathlib import Path
from datetime import datetime

class PatchDiffer:
    def __init__(self, work_dir, target_files):
        self.work_dir = Path(work_dir)
        self.target_files = target_files
        self.results = []

    def diff_binaries(self, old_dir, new_dir, output_dir):
        """Run ghidriff on all target binaries"""

        old_path = Path(old_dir)
        new_path = Path(new_dir)
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        for target in self.target_files:
            old_file = self.find_file(old_path, target)
            new_file = self.find_file(new_path, target)

            if not old_file or not new_file:
                print(f"[-] Skipping {target}: files not found")
                continue

            print(f"[+] Diffing {target}...")

            diff_name = f"{target.replace('.', '_')}_diff"
            diff_out = out_path / diff_name

            cmd = [
                "ghidriff",
                str(old_file),
                str(new_file),
                "--output", str(diff_out),
                "--symbols-path", "C:\\patch-analysis\\symbols\\",
                "--max-section-funcs", "5000",
                "--max-ram-percent", "80"
            ]

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)

                if result.returncode == 0:
                    print(f"[+] Success: {diff_name}")
                    self.parse_results(diff_out, target)
                else:
                    print(f"[-] Error diffing {target}: {result.stderr}")

            except subprocess.TimeoutExpired:
                print(f"[-] Timeout diffing {target}")
            except Exception as e:
                print(f"[-] Exception diffing {target}: {e}")

    def find_file(self, directory, filename):
        """Recursively find file in directory"""
        for path in directory.rglob(filename):
            return path
        return None

    def parse_results(self, diff_dir, binary_name):
        """Parse ghidriff JSON output

        ghidriff outputs to: <output_dir>/json/<old>-<new>.ghidriff.json
        The JSON structure uses 'functions.added', 'functions.deleted', 'functions.modified'
        """
        # ghidriff puts JSON files in a 'json' subdirectory or 'ghidriffs/json'
        json_patterns = [
            diff_dir / "json" / "*.ghidriff.json",
            diff_dir / "*.ghidriff.json",
            diff_dir.parent / "ghidriffs" / "json" / "*.ghidriff.json",
        ]

        json_file = None
        for pattern in json_patterns:
            matches = glob.glob(str(pattern))
            if matches:
                json_file = Path(matches[0])
                break

        if not json_file or not json_file.exists():
            print(f"[-] No JSON output found for {binary_name}")
            return

        with open(json_file) as f:
            data = json.load(f)

        # ghidriff uses nested structure: data['functions']['added'], etc.
        functions = data.get("functions", {})
        added = functions.get("added", [])
        deleted = functions.get("deleted", [])
        modified = functions.get("modified", [])

        summary = {
            "binary": binary_name,
            "total_funcs": data.get("stats", {}).get("total_functions", len(added) + len(deleted) + len(modified)),
            "matched": data.get("stats", {}).get("matched", 0),
            "changed": len(modified),
            "new": len(added),
            "deleted": len(deleted),
            "changed_details": []
        }

        # Extract changed functions with low similarity
        # ghidriff modified entries have 'ratio' field and 'old'/'new' sub-objects
        for func in modified:
            ratio = func.get("ratio", 1.0)
            if ratio < 0.95:
                old_info = func.get("old", {})
                new_info = func.get("new", {})
                summary["changed_details"].append({
                    "name": old_info.get("name") or new_info.get("name", "unknown"),
                    "similarity": ratio,
                    "address_old": old_info.get("address", ""),
                    "address_new": new_info.get("address", "")
                })

        self.results.append(summary)

    def generate_report(self, output_file):
        """Generate HTML report"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Patch Diff Report - {datetime.now().strftime('%Y-%m-%d')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        .changed {{ color: #FF5722; font-weight: bold; }}
        .highlight {{ background-color: #FFEB3B; }}
    </style>
</head>
<body>
    <h1>Windows Patch Diff Analysis</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
"""

        for result in self.results:
            html += f"""
    <h2>{result['binary']}</h2>
    <table>
        <tr>
            <th>Metric</th>
            <th>Count</th>
        </tr>
        <tr>
            <td>Total Functions</td>
            <td>{result['total_funcs']}</td>
        </tr>
        <tr>
            <td>Matched</td>
            <td>{result['matched']}</td>
        </tr>
        <tr class="changed">
            <td>Changed</td>
            <td>{result['changed']}</td>
        </tr>
        <tr>
            <td>New</td>
            <td>{result['new']}</td>
        </tr>
        <tr>
            <td>Deleted</td>
            <td>{result['deleted']}</td>
        </tr>
    </table>
"""

            if result['changed_details']:
                html += """
    <h3>Changed Functions (Similarity < 0.95)</h3>
    <table>
        <tr>
            <th>Function Name</th>
            <th>Similarity</th>
            <th>Old Address</th>
            <th>New Address</th>
        </tr>
"""
                for func in result['changed_details']:
                    html += f"""
        <tr class="highlight">
            <td>{func['name']}</td>
            <td>{func['similarity']:.2f}</td>
            <td>{func['address_old']}</td>
            <td>{func['address_new']}</td>
        </tr>
"""
                html += "    </table>\n"

        html += """
</body>
</html>
"""

        with open(output_file, 'w') as f:
            f.write(html)

        print(f"[+] Report generated: {output_file}")

# Usage
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 4:
        print("Usage: python ghidriff_batch.py <old_kb_dir> <new_kb_dir> <output_dir>")
        print("")
        print("Arguments:")
        print("  old_kb_dir   Directory containing vulnerable binaries")
        print("  new_kb_dir   Directory containing patched binaries")
        print("  output_dir   Directory for diff output and reports")
        print("")
        print("Example:")
        print("  python ghidriff_batch.py ./binaries/KB5041565 ./binaries/KB5041571 ./diffs/august2024")
        sys.exit(1)

    old_dir = sys.argv[1]
    new_dir = sys.argv[2]
    out_dir = sys.argv[3]

    # Default high-value targets for Windows patch analysis
    targets = ["ntdll.dll", "win32k.sys", "tcpip.sys", "ntoskrnl.exe"]

    differ = PatchDiffer(out_dir, targets)
    differ.diff_binaries(old_dir, new_dir, out_dir)
    differ.generate_report(os.path.join(out_dir, "report.html"))
```

#### Scheduled Automation (Windows Task Scheduler)

**Create Monthly Task**:

```bash
# TODO: dear student, try to make this work

# Create scheduled task for Patch Tuesday analysis
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-File C:\patch-analysis\monthly_diff.ps1"

# Trigger: Second Wednesday of every month (day after Patch Tuesday)
$trigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 4 -DaysOfWeek Wednesday

# Settings
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries -StartWhenAvailable

# Register task
Register-ScheduledTask -TaskName "MonthlyPatchDiff" `
    -Action $action -Trigger $trigger -Settings $settings `
    -Description "Automated Windows patch diffing"
```

**Monthly Script (monthly_diff.ps1)**:

```bash
# TODO: dear student, try to make this work

# Monthly patch diff automation script
# Note: Requires manual download of .msu files or browser automation

$patchDir = "C:\patch-analysis"

# Get latest KB from MSRC CVRF API
# NOTE: This endpoint typically requires an MSRC API token / auth header and
# may change over time. Treat this as an example and consult MSRC docs.
try {
    $cvrf = Invoke-RestMethod -Uri "https://api.msrc.microsoft.com/cvrf/v2.0/updates" -ErrorAction Stop
    $latestKB = ($cvrf.value | Sort-Object -Property ReleaseDate -Descending | Select-Object -First 1).ID
    Write-Host "[+] Latest KB: $latestKB"
} catch {
    Write-Warning "[-] Failed to fetch from MSRC API. Check manually: https://msrc.microsoft.com/update-guide/"
    exit 1
}

# Download and analyze (requires manual .msu download)
# TODO: write this script yourself based on `Extract-Patch.ps1` from week 1
& "$patchDir\scripts\Windows11-Patch-Downloader.ps1" -KBNumber $latestKB

# Get previous month's KB (from tracking file)
$trackingFile = "$patchDir\last_kb.txt"
if (Test-Path $trackingFile) {
    $previousKB = Get-Content $trackingFile
} else {
    Write-Warning "[-] No previous KB found. Skipping diff."
    Set-Content $trackingFile -Value $latestKB
    exit 0
}

# Run diff (requires Python and ghidriff)
$pythonPath = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $pythonPath) {
    Write-Warning "[-] Python not found. Install Python 3.10+"
    exit 1
}

& $pythonPath "$patchDir\scripts\ghidriff_batch.py" `
    "$patchDir\$previousKB\binaries" `
    "$patchDir\$latestKB\binaries" `
    "$patchDir\diffs\$latestKB"

# Update tracking
Set-Content $trackingFile -Value $latestKB

# Send email notification (optional, requires SMTP configuration)
# Send-MailMessage -To "security@company.com" `
#     -From "patchdiff@company.com" `
#     -Subject "Patch Diff Report: $latestKB" `
#     -Body "See attached report" `
#     -Attachments "$patchDir\diffs\$latestKB\report.html" `
#     -SmtpServer "smtp.company.com"
```

### Practical Exercise

**Task**: Build and test your automated patch diffing pipeline

This exercise walks you through creating a reusable automation workflow that you can run monthly after each Patch Tuesday.

#### Part 1: Environment Setup

```bash
# Create workspace structure
$patchAnalysis = "C:\patch-analysis"
New-Item -ItemType Directory -Force -Path @(
    "$patchAnalysis\scripts",
    "$patchAnalysis\automated",
    "$patchAnalysis\diffs",
    "$patchAnalysis\symbols",
    "$patchAnalysis\reports"
)
cd $patchAnalysis

# Save the Extract-Patch.ps1 script from Day 1 to scripts folder
# Save ghidriff_batch.py to scripts folder

# Verify tools are available
ghidriff
python --version
```

#### Part 2: Acquire Consecutive Updates

```bash
# Choose two consecutive monthly updates (example: August vs September 2024)
$oldKB = "KB5041571"  # August 2024
$newKB = "KB5043178"  # September 2024

# Download vulnerable versions
New-Item -ItemType Directory -Force -Path ".\automated\$oldKB"
powershell -ExecutionPolicy Bypass -Command ".\scripts\Extract-Patch.ps1 -UseWinbIndex -KBNumber '$oldKB' -TargetBinaries @('tcpip.sys','ntdll.dll','win32k.sys','ntoskrnl.exe')"
Move-Item .\binaries\*.* ".\automated\$oldKB\" -Force

# Download patched versions
New-Item -ItemType Directory -Force -Path ".\automated\$newKB"
powershell -ExecutionPolicy Bypass -Command ".\scripts\Extract-Patch.ps1 -UseWinbIndex -KBNumber '$newKB' -TargetBinaries @('tcpip.sys','ntdll.dll','win32k.sys','ntoskrnl.exe')"
Move-Item .\binaries\*.* ".\automated\$newKB\" -Force

# Verify versions are different
Get-ChildItem ".\automated\$oldKB" | ForEach-Object {
    $old = (Get-Item $_.FullName).VersionInfo.FileVersion
    $newFile = ".\automated\$newKB\$($_.Name)"
    if (Test-Path $newFile) {
        $new = (Get-Item $newFile).VersionInfo.FileVersion
        Write-Host "$($_.Name): $old -> $new"
    }
}
```

#### Part 3: Download Symbols

```bash
# Download symbols for both versions (enables better function names)
$symchk = 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe'

& $symchk /r "C:\patch-analysis\automated\$oldKB" /s "SRV*C:\patch-analysis\symbols*https://msdl.microsoft.com/download/symbols"
& $symchk /r "C:\patch-analysis\automated\$newKB" /s "SRV*C:\patch-analysis\symbols*https://msdl.microsoft.com/download/symbols"

# Verify symbols downloaded
Get-ChildItem ".\symbols" -Recurse -Filter "*.pdb" | Measure-Object
```

#### Part 4: Run Batch Diff

```bash
# Run the batch diffing script
$outputDir = ".\diffs\$($oldKB)_vs_$($newKB)"
python .\scripts\ghidriff_batch.py ".\automated\$oldKB" ".\automated\$newKB" $outputDir

# Monitor progress in the console output
```

#### Part 5: Analyze Results

```bash
# Open the generated HTML report
Start-Process "$outputDir\report.html"

# Also review the raw ghidriff markdown for detailed diffs
Get-ChildItem $outputDir -Recurse -Filter "*.ghidriff.md" | ForEach-Object {
    Write-Host "Diff report: $($_.FullName)"
}
```

**Analysis Questions to Answer**:

1. Which binaries had the most changed functions?
2. Are there functions with similarity < 0.90? (High-priority for review)
3. Do any function names suggest security fixes? (Look for: Validate, Check, Bounds, Safe, Sanitize)
4. Are there new functions added? (Could be new security checks)
5. Cross-reference with [MSRC Security Update Guide](https://msrc.microsoft.com/update-guide/) - do the changed binaries match announced CVEs?

#### Part 6: Create Monthly Automation (Optional)

```bash
# TODO: dear student, change it so it can work correctly

$monthlyScript = @'
# monthly_patch_diff.ps1
param(
    [Parameter(Mandatory=$true)]
    [string]$OldKB,

    [Parameter(Mandatory=$true)]
    [string]$NewKB
)

$patchDir = "C:\patch-analysis"
$targets = @("tcpip.sys", "ntdll.dll", "win32k.sys", "ntoskrnl.exe", "afd.sys")
$symchk = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe"

# Download binaries
foreach ($kb in @($OldKB, $NewKB)) {
    $kbDir = "$patchDir\automated\$kb"
    if (-not (Test-Path $kbDir)) {
        New-Item -ItemType Directory -Force -Path $kbDir | Out-Null
        Push-Location $patchDir
        $targetList = $targets -join "','"
        powershell -Command ".\scripts\Extract-Patch.ps1 -UseWinbIndex -KBNumber '$kb' -TargetBinaries @('$targetList')"
        Move-Item .\binaries\*.* $kbDir -Force -ErrorAction SilentlyContinue
        & $symchk /r "C:\patch-analysis\automated\'$kb'" /s "SRV*C:\patch-analysis\symbols*https://msdl.microsoft.com/download/symbols"
        Pop-Location
    }
}

# Run diff
$outputDir = "$patchDir\diffs\$($OldKB)_vs_$($NewKB)"
python "$patchDir\scripts\ghidriff_batch.py" "$patchDir\automated\$OldKB" "$patchDir\automated\$NewKB" $outputDir

# Open report
Start-Process "$outputDir\report.html"

Write-Host "[+] Analysis complete: $outputDir"
'@

$monthlyScript | Out-File ".\scripts\monthly_patch_diff.ps1" -Encoding UTF8

# Usage:
# .\scripts\monthly_patch_diff.ps1 -OldKB "KB5040442" -NewKB "KB5041571"
```

**Success Criteria**:

- Workspace directories created and organized
- Both KB versions downloaded with correct file versions
- Symbols downloaded for at least 50% of binaries
- ghidriff_batch.py runs without errors
- HTML report generated with function statistics
- At least 3 target binaries successfully diffed
- Identified changed functions with similarity scores < 0.95
- Cross-referenced at least one finding with MSRC advisory

**Troubleshooting Common Issues**:

| Issue                           | Solution                                                                  |
| ------------------------------- | ------------------------------------------------------------------------- |
| "ghidriff not found"            | Ensure Python Scripts folder is in PATH, or use full path to ghidriff.exe |
| Version mismatch from WinbIndex | Download .msu manually and extract, or use UUP Dump                       |
| Out of memory during diff       | Reduce `--max-section-funcs` or diff one binary at a time                 |
| No symbols downloaded           | Check symchk output for errors; some binaries may not have public symbols |
| Empty diff report               | Verify both versions are actually different (check FileVersion)           |

### LLM-Assisted Patch Summarization

Combining ghidriff output with Large Language Models can accelerate patch analysis:

**Workflow**:

1. Generate ghidriff markdown output
2. Feed the diff to an LLM with security context
3. Get automated vulnerability summaries

**Example Prompt Template**:

```text
You are a vulnerability researcher analyzing a binary patch diff.

Context:
- This diff compares a vulnerable Windows driver to its patched version
- Focus on security-relevant changes (bounds checks, validation, error handling)
- Ignore cosmetic changes (variable renaming, code movement without logic changes)

Analyze this patch diff and provide:
1. VULNERABILITY CLASS: What type of bug is being fixed? (buffer overflow, integer overflow, UAF, race condition, logic error, etc.)
2. AFFECTED FUNCTIONS: List the functions that contain security-relevant changes
3. ROOT CAUSE: What was the underlying programming mistake?
4. FIX DESCRIPTION: What validation or checks were added?
5. ATTACK VECTOR: How might an attacker have triggered this vulnerability?
6. BYPASS POTENTIAL: Are there any obvious ways the fix might be incomplete?

Patch Diff:
[paste ghidriff markdown output - focus on functions with <0.95 similarity]
```

> [!WARNING]
> **LLM Limitations for Patch Analysis**:
>
> - LLMs can hallucinate vulnerability details that don't exist
> - They may miss subtle bugs that require deep domain knowledge
> - Assembly/decompiled code analysis is not their strength
> - Always verify LLM findings by examining the actual code
> - Use LLMs for initial triage and hypothesis generation, not as the final word

**When LLMs Help Most**:

- Summarizing large diffs with many changed functions
- Generating initial hypotheses about vulnerability class
- Explaining unfamiliar code patterns
- Drafting report sections (with verification)

**When LLMs Struggle**:

- Subtle race conditions or timing issues
- Complex pointer arithmetic and bounds calculations
- Understanding Windows kernel internals without context
- Distinguishing security fixes from optimization changes

### Key Takeaways

1. **Automation transforms patch analysis from reactive to proactive**: Instead of waiting for public PoCs, you can analyze patches within hours of release and understand vulnerabilities before exploits appear in the wild.

2. **The pipeline has clear stages with different failure modes**:
   - **Acquisition**: WinbIndex collisions, delta-only updates, missing binaries
   - **Extraction**: PSF format changes, nested CAB structures, corrupted packages
   - **Diffing**: Memory limits, timeout on large binaries, missing symbols
   - **Analysis**: Compiler noise, false positives, missing context

3. **Symbols are force multipliers**: A diff with symbols shows `IppValidatePacketLength` changed; without symbols, you see `sub_1400A2F40` changed. Invest time in symbol acquisition.

4. **Prioritization is critical for scale**: A cumulative update may change 500+ functions across 20 binaries. Use heuristics:
   - Similarity < 0.90 = significant change
   - Security-relevant function names (Validate, Check, Bounds, Parse)
   - Binaries mentioned in MSRC advisories
   - Network-facing components (tcpip.sys, http.sys, afd.sys)

5. **Automation enables pattern recognition over time**: After analyzing 6-12 months of patches, you'll recognize Microsoft's fix patterns:
   - Integer overflow → `RtlULongAdd`, `RtlSizeTMult` usage
   - Buffer overflow → `_s` suffix functions, explicit size checks
   - UAF → Reference counting changes, deferred cleanup
   - Logic bugs → Additional `if` conditions, early returns

6. **Documentation pays dividends**: Keep notes on each analysis. Future patches to the same component become easier when you understand the code.

7. **Tools evolve; adapt your pipeline**: ghidriff, WinbIndex, and Windows Update formats all change. Budget time for maintenance.

### Discussion Questions

1. **Timing**: Microsoft releases patches on the second Tuesday of each month. Security researchers often race to analyze patches before attackers can weaponize them.
   - Should automated patch analysis tools be publicly available, or does this help attackers more than defenders?
   - What's the difference between "patch diffing for defense" and "patch diffing for offense"?

2. **Automation vs. Understanding**: Automated pipelines can process dozens of binaries overnight, but may miss subtle vulnerabilities that require human insight.
   - How do you balance breadth (analyze everything) vs. depth (understand thoroughly)?
   - What signals should trigger deeper manual analysis?
   - Can automation replace the need to understand Windows internals, or is it just a force multiplier?

3. **False Positives and Noise**: Large updates contain many non-security changes mixed with actual fixes.
   - What filtering strategies work best for isolating security-relevant changes?
   - How do you handle compiler optimizations that make identical code look different?
   - Should you track "interesting" non-security changes that might become vulnerabilities later?

4. **Data Sources and Correlation**: Patch diffs are one piece of the puzzle.
   - What other data sources could enhance automated analysis? (MSRC advisories, syzkaller reports, GitHub commits, Twitter/X discussions)
   - How would you correlate a binary diff with source-level commits for open-source components in Windows?
   - Could you automate CVE-to-function mapping by combining MSRC descriptions with diff output?

5. **Scaling and Prioritization**: Microsoft patches Windows, Office, Edge, Exchange, Azure, and more.
   - How would you prioritize which products/components to analyze first?
   - What metrics indicate a patch is "high priority" for analysis? (CVSS, exploitability, attack surface)
   - Could you build a scoring system to automatically rank patches by security relevance?

6. **LLM Integration**: Large Language Models can summarize diffs but have limitations.
   - What tasks are LLMs good at in patch analysis? What should they never do unsupervised?
   - How would you validate LLM-generated vulnerability summaries?
   - Could LLMs help generate initial PoC hypotheses, or is this too risky?

## Day 5: Linux Kernel Patch Diffing

- **Goal**: Apply patch diffing techniques to Linux kernel updates.
- **Activities**:
  - _Reading_:
    - [Linux Kernel Development Process](https://www.kernel.org/doc/html/latest/process/development-process.html)
    - [Google Project Zero Posts](https://googleprojectzero.blogspot.com/)
    - [Google's kernel exploitation competition](https://google.github.io/security-research/kernelctf/rules.html)
  - _Online Resources_:
    - [Ubuntu Security Notices API](https://ubuntu.com/security/notices)
    - [Debian Security Tracker](https://security-tracker.debian.org/)
    - [kernel.org Git Repository](https://git.kernel.org/)
    - [Linux Kernel CVEs](https://lore.kernel.org/linux-cve-announce/)
    - [syzbot Dashboard](https://syzkaller.appspot.com/)

  - _Tool Setup_:
    - Ubuntu/Debian system (VM or WSL2)
    - Ghidra 11.4+ or IDA Pro
  - _Exercise_:
    - Diff Linux kernel between two versions
    - Identify io_uring or network stack changes

### Linux Kernel Patch Diffing Workflow

**Differences from Windows**:

- Source code often available (but not always for vendor kernels)
- Binaries are ELF format
- Distribution-specific modifications complicate diffing
- DWARF debug symbols instead of PDB

#### Step 1: Identify Target Kernel Builds

**Ubuntu Example**:

```bash
# Get current kernel version and store it for use throughout this exercise
CURRENT_KERNEL=$(uname -r)
echo "Current kernel: $CURRENT_KERNEL"
# Example output: 6.8.0-87-generic

# Extract the base version (e.g., 6.8.0) and patch number (e.g., 87)
KERNEL_BASE=$(echo $CURRENT_KERNEL | sed 's/-[0-9]*-generic//')
KERNEL_PATCH=$(echo $CURRENT_KERNEL | grep -oP '(?<=-)[0-9]+(?=-generic)')
KERNEL_FLAVOR=$(echo $CURRENT_KERNEL | grep -oP '[a-z]+$')  # e.g., "generic"

echo "Base: $KERNEL_BASE, Patch: $KERNEL_PATCH, Flavor: $KERNEL_FLAVOR"

# Calculate previous kernel version (patch - 1)
PREV_PATCH=$((KERNEL_PATCH - 1))
PREV_KERNEL="${KERNEL_BASE}-${PREV_PATCH}-${KERNEL_FLAVOR}"
echo "Previous kernel: $PREV_KERNEL"

# Find available kernel versions
apt list -a linux-image-generic 2>/dev/null | grep -E "^linux-image-generic"
# Example output:
# linux-image-generic/noble-updates,noble-security,now 6.8.0-87.88 amd64 [installed,automatic]
# linux-image-generic/noble 6.8.0-31.31 amd64

# Or use apt-cache
apt-cache policy linux-image-generic

# Identify security updates from Ubuntu security notices
# Install jq if needed: sudo apt install -y jq
# Search for kernel-related notices (use offset to paginate, limit max 20)
curl -s 'https://ubuntu.com/security/notices.json?offset=50' | \
    jq '.notices[] | select(.title | ascii_downcase | contains("kernel")) | {id, title, published}'

# Or check for 2025 CVEs
curl -s https://ubuntu.com/security/notices.json | \
    jq '.notices[] | select(.cves_ids[] | startswith("CVE-2025-")) | {title, cves: .cves_ids}'
```

#### Step 2: Download Kernel Images and Debug Symbols

**Ubuntu/Debian**:

```bash
# Create workspace
mkdir ~/kernel-diff && cd ~/kernel-diff
mkdir old new symbols

# Use the kernel versions we identified in Step 1
# If you're in a new shell, re-run the version detection:
#CURRENT_KERNEL=$(uname -r)
#KERNEL_BASE=$(echo $CURRENT_KERNEL | sed 's/-[0-9]*-generic//')
#KERNEL_PATCH=$(echo $CURRENT_KERNEL | grep -oP '(?<=-)[0-9]+(?=-generic)')
#KERNEL_FLAVOR=$(echo $CURRENT_KERNEL | grep -oP '[a-z]+$')
#PREV_PATCH=$((KERNEL_PATCH - 1))
#PREV_KERNEL="${KERNEL_BASE}-${PREV_PATCH}-${KERNEL_FLAVOR}"

echo "Downloading kernels:"
echo "  Old (vulnerable): $PREV_KERNEL"
echo "  New (patched):    $CURRENT_KERNEL"

# Download older version (previous patch level)
apt-get download linux-image-unsigned-${PREV_KERNEL}
dpkg-deb -x linux-image-unsigned-${PREV_KERNEL}_*.deb old/

# Download newer version (current)
apt-get download linux-image-unsigned-${CURRENT_KERNEL}
dpkg-deb -x linux-image-unsigned-${CURRENT_KERNEL}_*.deb new/
```

**Debug Symbols**:

Debug symbols provide function names and source mappings. There are multiple ways to obtain them:

```bash
# Method 1: Use debuginfod (automatic, requires network during analysis)
export DEBUGINFOD_URLS="https://debuginfod.ubuntu.com"
# Tools like gdb and addr2line will automatically fetch symbols as needed

# Method 2: Download dbgsym packages manually
# First, add the ddebs repository:
echo "deb http://ddebs.ubuntu.com $(lsb_release -cs) main restricted universe multiverse" | \
    sudo tee /etc/apt/sources.list.d/ddebs.list
echo "deb http://ddebs.ubuntu.com $(lsb_release -cs)-updates main restricted universe multiverse" | \
    sudo tee -a /etc/apt/sources.list.d/ddebs.list

# Import the signing key
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys F2EDC64DC5AEE1F6B9C621F0C8CAB6595FDFF622
sudo apt-get update

# Download debug symbols packages
apt-get download linux-image-unsigned-${PREV_KERNEL}-dbgsym
apt-get download linux-image-unsigned-${CURRENT_KERNEL}-dbgsym

# Extract dbgsym packages (contains vmlinux with debug info)
dpkg-deb -x linux-image-unsigned-${PREV_KERNEL}-dbgsym_*.ddeb old/
dpkg-deb -x linux-image-unsigned-${CURRENT_KERNEL}-dbgsym_*.ddeb new/

# The debug vmlinux will be at:
# old/usr/lib/debug/boot/vmlinux-${PREV_KERNEL}
# new/usr/lib/debug/boot/vmlinux-${CURRENT_KERNEL}
```

#### Step 3: Extract or Locate vmlinux

The `vmlinux` file is the uncompressed kernel image needed for binary diffing. There are several ways to obtain it depending on what packages you downloaded:

**Option A: From dbgsym package (Best - includes debug symbols)**

If you downloaded and extracted the `-dbgsym` packages in Step 2:

```bash
cd ~/kernel-diff/old

# Find the vmlinux with debug symbols
find . -name "vmlinux*" -type f
# Expected output: ./usr/lib/debug/boot/vmlinux-6.8.0-86-generic

# Copy to working location
cp ./usr/lib/debug/boot/vmlinux-${PREV_KERNEL} ~/kernel-diff/old/vmlinux

# Verify it has symbols (should show many symbols, not "no symbols")
file ~/kernel-diff/old/vmlinux
# Expected: ELF 64-bit LSB executable... with debug_info, not stripped

nm ~/kernel-diff/old/vmlinux | head -5
# Should show function names like:
#ffffffff81773ba0 T aa_af_perm
#ffffffff81759760 T aa_alloc_null
#ffffffff81758d60 T aa_alloc_pdb
#ffffffff81759040 T aa_alloc_profile
#ffffffff8176c840 T aa_alloc_proxy
```

**Option B: Extract from vmlinuz (Stripped - no debug symbols)**

If you only have the regular kernel package (not dbgsym), you can extract vmlinux from the compressed vmlinuz:

```bash
cd ~/kernel-diff/old/boot
ls -lh vmlinuz-*
# Example: vmlinuz-6.8.0-86-generic (compressed, ~15MB)

# Method 1: Use kernel headers script (if installed)
/usr/src/linux-headers-${CURRENT_KERNEL}/scripts/extract-vmlinux \
    vmlinuz-${PREV_KERNEL} > ~/kernel-diff/old/vmlinux

# Method 2: Download extract-vmlinux script directly
wget -q https://raw.githubusercontent.com/torvalds/linux/master/scripts/extract-vmlinux
chmod +x extract-vmlinux
./extract-vmlinux vmlinuz-${PREV_KERNEL} > ~/kernel-diff/old/vmlinux

# Verify extraction worked
file ~/kernel-diff/old/vmlinux
# Expected: ELF 64-bit LSB executable, x86-64... statically linked, stripped
# Note: "stripped" means no debug symbols - function names will be missing
```

**Repeat for the new/patched kernel:**

```bash
cd ~/kernel-diff/new
# Use the same method (A, B) to obtain vmlinux for the patched version
```

#### Step 4: Identify Changed Modules

```bash
# Compare module trees
cd ~/kernel-diff

diff -qr old/usr/lib/debug/lib/modules/${PREV_KERNEL}/kernel/ new/usr/lib/debug/lib/modules/${CURRENT_KERNEL}/kernel/ | grep differ


# Focus on specific subsystems
diff -qr old/usr/lib/debug/lib/modules/${PREV_KERNEL}/kernel/net new/usr/lib/debug/lib/modules/${CURRENT_KERNEL}/kernel/net
diff -qr old/usr/lib/debug/lib/modules/${PREV_KERNEL}/kernel/fs/overlayfs/ new/usr/lib/debug/lib/modules/${CURRENT_KERNEL}/kernel/fs/overlayfs/
```

#### Step 5: Install Ghidra and Ghidriff on Linux

Before running binary diffs, you need to install Ghidra and ghidriff. The Windows installation was covered in Day 2 (Option 4). Here's the Linux setup:

```bash
sudo apt update
sudo apt install -y openjdk-21-jdk
export JAVA_HOME=$(dirname $(dirname $(readlink -f $(which java))))
echo "export JAVA_HOME=$JAVA_HOME" >> ~/.bashrc
mkdir -p ~/tools && cd ~/tools
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.4.2_build/ghidra_11.4.2_PUBLIC_20250826.zip
unzip ghidra_11.4.2_PUBLIC_20250826.zip
export GHIDRA_INSTALL_DIR=~/tools/ghidra_11.4.2_PUBLIC
echo "export GHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR" >> ~/.bashrc
sudo ln -s ~/tools/ghidra_11.4.2_PUBLIC/ghidraRun /usr/local/bin/ghidra
sudo apt install -y python3 python3-pip python3-venv
python3 -m venv ~/ghidriff-env
source ~/ghidriff-env/bin/activate
pip install ghidriff
ghidriff --help
# Should show usage information without errors
```

#### Step 6: Binary Diffing with Ghidra

**Module-Specific Diff**:

```bash
# First, decompress the modules (Ubuntu uses .ko.zst)
cd ~/kernel-diff

# Decompress a specific module for diffing
# check https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/noble/log/?h=Ubuntu-6.8.0-86.87 for possible changes, change kernel versions to your liking
zstd -d old/usr/lib/debug/lib/modules/${PREV_KERNEL}/kernel/drivers/net/ethernet/intel/idpf/idpf.ko.zst -o old/idpf.ko
zstd -d new/usr/lib/debug/lib/modules/${CURRENT_KERNEL}/kernel/drivers/net/ethernet/intel/idpf/idpf.ko.zst -o new/idpf.ko

ghidriff old/idpf.ko new/idpf.ko --max-ram-percent 80 --max-section-funcs 3000 --output idpf_diff --no-threaded

# Comparing the entire vmlinux will take a lot of time, instead target specific components like above
ghidriff old/usr/lib/debug/boot/vmlinux-${PREV_KERNEL} \
    new/usr/lib/debug/boot/vmlinux-${CURRENT_KERNEL} \
    --output core_diff \
    --max-ram-percent 80 \
    --max-section-funcs 3000 \
    --no-threaded

# TODO: try using ghidra's internal version tracking tool just like the windows section
```

#### Step 7: Source-Level Diff (When Available)

**Using Git**:

```bash
# Clone kernel source (use a stable version, check https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/refs/tag
cd ~/kernel-diff
git clone --branch v6.8 https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git kernel-6.8

# Find commit for specific CVE
cd kernel-6.8
git log --all --grep="CVE" --oneline

# Show commit diff
git show 118082368c2b

# Or use GitHub directly (easier to browse):
# https://github.com/torvalds/linux/commit/<commit-hash>

# Search for fixes in specific subsystem
git log --all --oneline --grep="overlayfs" --grep="CVE" | head -10
```

#### Step 8: Analyze Specific CVE Fix

**Example 1: CVE-2024-1086 (nf_tables UAF) - High-Profile LPE**

This vulnerability affected all Linux kernels from 3.15 to 6.8 and had a public exploit achieving reliable root:

```bash
git show f342de4e2f33e0e39165d8639387aa6c19dff660

# The fix is surprisingly simple:
#diff --git a/net/netfilter/nf_tables_api.c b/net/netfilter/nf_tables_api.c
#index 02f45424644b..c537104411e7 100644
#--- a/net/netfilter/nf_tables_api.c
#+++ b/net/netfilter/nf_tables_api.c
#@@ -10992,16 +10992,10 @@ static int nft_verdict_init(const struct nft_ctx *ctx, struct nft_data *data,
#        data->verdict.code = ntohl(nla_get_be32(tb[NFTA_VERDICT_CODE]));
#
#        switch (data->verdict.code) {
#-       default:
#-               switch (data->verdict.code & NF_VERDICT_MASK) {
#-               case NF_ACCEPT:
#-               case NF_DROP:
#-               case NF_QUEUE:
#-                       break;
#-               default:
#-                       return -EINVAL;
#-               }
#-               fallthrough;
#+       case NF_ACCEPT:
#+       case NF_DROP:
#+       case NF_QUEUE:
#+               break;
#        case NFT_CONTINUE:
#        case NFT_BREAK:
#        case NFT_RETURN:
#@@ -11036,6 +11030,8 @@ static int nft_verdict_init(const struct nft_ctx *ctx, struct nft_data *data,
#
#                data->verdict.chain = chain;
#                break;
#+       default:
#+               return -EINVAL;
#        }
```

**Analysis**:

- **Bug Type**: Use-After-Free via verdict value confusion
- **Location**: `net/netfilter/nf_tables_api.c:nft_verdict_init()`
- **Root Cause**: Old code used `& NF_VERDICT_MASK` to validate verdicts, allowing values like `NF_DROP | extra_bits` to pass. These "decorated" verdicts caused type confusion in later code paths.
- **Impact**: Reliable local privilege escalation (LPE)
- **Exploit**: Public exploit by @Notselwyn achieves ~99% success rate
- **Fix**: Changed from mask-based validation to exact match validation, rejecting any verdict with extra bits set

**Why This Matters for Patch Diffing**:

- The fix restructures ~15 lines, but understanding WHY required deep nf_tables knowledge
- Demonstrates how mask vs exact-match validation can have critical security implications
- Public exploit provides validation of patch analysis

**Example 2: CVE-2024-26585**

```bash
git show e01e3934a1b2d122919f73bc6ddbe1cdafc4bbdb

#diff --git a/net/tls/tls_sw.c b/net/tls/tls_sw.c
#index 635305bebfef..9374a61cef00 100644
#--- a/net/tls/tls_sw.c
#+++ b/net/tls/tls_sw.c
#@@ -447,7 +447,6 @@ static void tls_encrypt_done(void *data, int err)
#        struct tls_rec *rec = data;
#        struct scatterlist *sge;
#        struct sk_msg *msg_en;
#-       bool ready = false;
#        struct sock *sk;
#
#        msg_en = &rec->msg_encrypted;
#@@ -483,19 +482,16 @@ static void tls_encrypt_done(void *data, int err)
#                /* If received record is at head of tx_list, schedule tx */
#                first_rec = list_first_entry(&ctx->tx_list,
#                                             struct tls_rec, list);
#-               if (rec == first_rec)
#-                       ready = true;
#+               if (rec == first_rec) {
#+                       /* Schedule the transmission */
#+                       if (!test_and_set_bit(BIT_TX_SCHEDULED,
#+                                             &ctx->tx_bitmask))
#+                               schedule_delayed_work(&ctx->tx_work.work, 1);
#+               }
#        }
#
#        if (atomic_dec_and_test(&ctx->encrypt_pending))
#                complete(&ctx->async_wait.completion);
#-
#-       if (!ready)
#-               return;
#-
#-       /* Schedule the transmission */
#-       if (!test_and_set_bit(BIT_TX_SCHEDULED, &ctx->tx_bitmask))
#-               schedule_delayed_work(&ctx->tx_work.work, 1);
# }
```

**Analysis**:

- **Bug Type**: Race Condition (CWE-362)
- **Location**: `net/tls/tls_sw.c:tls_encrypt_done()`
- **Root Cause**: In the original code, the `ready` flag was set inside a locked section when `rec == first_rec`, but the actual `schedule_delayed_work()` call happened after `atomic_dec_and_test()` completed. This created a race window where `ctx` could be freed by another thread after the lock was released and `encrypt_pending` reached zero, but before the work was scheduled.
- **Fix**: Moved the `schedule_delayed_work()` call inside the locked section immediately after checking `rec == first_rec`, ensuring the scheduling happens atomically with the check before any potential cleanup.
- **Impact**: Use-after-free leading to potential privilege escalation or denial of service in TLS socket handling
- **Trigger**: Concurrent TLS encryption operations with specific timing

**Example 3: CVE-2024-0582**

```bash
git show c392cbecd8eca4c53f2bf508731257d9d0a21c2d

# io_uring bugs often involve:
# - Reference counting errors
# - Race conditions
# - Improper resource cleanup
```

**Why io_uring is a Hot Target**:

- Complex async I/O subsystem added in Linux 5.1
- Frequent syzkaller findings
- High attack surface (many operations)
- Often enabled even in containers

**Searching for io_uring CVEs**:

```bash
# Find all io_uring security fixes
git log --all --oneline -- io_uring/ | grep -i "fix\|CVE\|security\|vuln"

# Or search for common patterns
git log --all --oneline -S "io_uring" --grep="use-after-free\|double-free\|overflow"
```

#### Step 9: Symbolization and Crash Mapping

**Decode Kernel Oops**:

```bash
cd ~/kernel-diff/kernel-6.8/

# Given a kernel crash log (dmesg output or syzkaller report - this is a non-working sample)
cat > crash.log << 'EOF'
BUG: KASAN: slab-out-of-bounds in crc32c+0xd0/0x460 lib/crc32.c:86
Read of size 8 at addr ffff888031d9e200 by task mount/6105

CPU: 1 UID: 0 PID: 6105 Comm: mount Not tainted
Call Trace:
 <TASK>
 dump_stack_lvl+0x189/0x250 lib/dump_stack.c:120
 kasan_report+0x118/0x150 mm/kasan/report.c:595
 crc32c+0xd0/0x460 lib/crc32.c:86
 xlog_cksum+0x92/0xf0 fs/xfs/xfs_log.c:1834
 xlog_recover_process+0x7a/0x1f0 fs/xfs/xfs_log_recover.c:2900
 xlog_do_recovery_pass+0x9cd/0xc30 fs/xfs/xfs_log_recover.c:3235
 xfs_log_mount+0x253/0x3e0 fs/xfs/xfs_log.c:667
 xfs_mountfs+0xe5e/0x2330 fs/xfs/xfs_mount.c:1031
EOF

./scripts/decode_stacktrace.sh \
    ~/kernel-diff/old/vmlinux \
    ~/kernel-diff/old/usr/lib/debug/lib/modules/${PREV_KERNEL}/ < crash.log

# Alternative: Use addr2line directly
# For core kernel functions, get the base address and add the offset from the crash:
sudo grep " crc32c$" /proc/kallsyms
# ffffffffc0438010 T crc32c

# Add offset 0xd0 to get crash location: base + 0xd0
addr2line -e ~/kernel-diff/old/vmlinux -f -C ffffffffc0438010
```

**Map Address to Source**:

```bash
# For module functions, use the debug module:
zstd -d old/usr/lib/debug/lib/modules/${PREV_KERNEL}/kernel/fs/xfs/xfs.ko.zst -o old/xfs.ko
addr2line -e ~/kernel-diff/old/xfs.ko -f 0x92
# Example output (actual addresses/functions depend on your kernel version):
# __traceiter_xfs_attr_list_sf_all
# /build/linux-lKDEjm/linux-6.8.0/fs/xfs/xfs_trace.c:138


# Or use gdb on the module with debug symbols:
gdb ~/kernel-diff/old/xfs.ko
(gdb) list *(xlog_cksum+0x92)
# 0xcabf2 is in xlog_cksum (/build/linux-lKDEjm/linux-6.8.0/fs/xfs/xfs_log.c:1834).
```

### Linux-Specific Considerations

**Compiler Optimizations**:

- Clang vs GCC produce different code
- `-O2` vs `-O3` significantly affects diff
- Link-Time Optimization (LTO) complicates analysis
- kcfi (kernel Control-Flow Integrity) adds thunks

> [!TIP]
> Filter by real function body deltas, ignore CFI stubs.

**Kernel Livepatch Considerations**:

Some distributions use kernel livepatch for security fixes:

```bash
# Check if livepatch is active
ls /sys/kernel/livepatch/

# Livepatch files are in /lib/modules/$(uname -r)/livepatch/
# These are separate .ko files that modify running kernel
```

Livepatch implications for diffing:

- Original vmlinux unchanged
- Fix is in separate livepatch module
- Must diff the livepatch .ko against nothing (new code)

**KCFI/FineIBT Changes**:

- Create many small stub changes
- Look for `__cfi_` prefixed functions
- Focus on substantial logic changes, not just landing pads

**Syzkaller Reports**:

- Consult [syzbot](https://syzkaller.appspot.com/) for reproducers
- Many bugs have C reproducer and syz script
- Helps validate your diff analysis

> [!TIP]
> Syzkaller routinely bisects kernel bugs to find introduction/fix commits.

### Practical Exercise

**Task**: Analyze recent Ubuntu kernel security update

1. **Download Two Consecutive Kernel Versions**
2. **Extract and Prepare**
3. **Identify Target Subsystem**
4. **Diff Specific Module**
5. **Verify Source-Level Changes**
6. **Document Findings**
   - What subsystem was affected?
   - What functions changed?
   - What was the root cause?
   - How was it fixed?

**Success Criteria**:

- Successfully extracted vmlinux from both versions
- Identified changed modules
- Completed binary diff with Ghidriff
- Correlated findings with source-level patch
- Understood the vulnerability and fix

### Key Takeaways

1. **Linux kernel diffing is more accessible**: Source often available, open development
2. **Distribution kernels add complexity**: Vendor patches, backports complicate analysis
3. **Module-level diffing is practical**: Full vmlinux diff is resource-intensive
4. **Source correlation is valuable**: Binary diff finds functions, source explains why
5. **Syzkaller is a goldmine**: Reproducers, bisection data, and crash reports

### Discussion Questions

1. How do Linux and Windows patch diffing workflows differ in practice?
2. What advantages does open-source kernel development provide for security research?
3. How can vendor-specific kernel patches complicate vulnerability analysis?
4. What role does syzkaller play in modern kernel security?

## Day 6: 7-Zip Case Study and Writing Reports

- **Goal**: Analyze a source-available vulnerability and learn to write professional patch diff reports.
- **Activities**:
  - _Reading_:
    - [7-Zip 25.00 Release Notes](https://www.7-zip.org/history.txt)
    - [Common Weakness Enumeration (CWE) Definitions](https://cwe.mitre.org/)
  - _Online Resources_:
    - [7-Zip Source Code](https://github.com/ip7z/7zip)
    - [ZDI Advisory Template](https://www.zerodayinitiative.com/advisories/)
    - [CWE-22: Improper Limitation of Pathname](https://cwe.mitre.org/data/definitions/22.html)
  - _Real-World Context_:
    - 7-Zip is widely used (100M+ downloads) making it a high-value target
    - Archive parsers are common attack vectors for initial access
    - Similar vulnerabilities exist in other archive tools (WinRAR, unzip, etc.)
  - _Concepts_:
    - Source-level patch analysis
    - Path traversal vulnerabilities
    - Professional vulnerability reporting
  - _Exercise_:
    - Analyze 7-Zip symlink fix
    - Write professional patch diff report

### Case Study: 7-Zip Symlink Path Traversal

In Week 1 you saw this 7-Zip symlink issue as an example of a logic/path-traversal bug. Here you will patch-diff the actual fix and practice turning that analysis into a professional report.

**Background**:

- **Software**: 7-Zip file archiver
- **Versions Affected**: 24.09 and earlier
- **Fixed In**: 25.00
- **Vulnerability Type**: Path Traversal via Symlink Handling (CWE-22)
- **Impact**: Arbitrary File Write (can lead to RCE via DLL hijacking, startup folder abuse)
- **CVSS**: Estimated 7.8 (High) - Local attack vector

**Discovery Method**: Source code review and patch analysis (versions are open-source).

#### Source-Level Patch Analysis

**Target File**: `CPP/7zip/UI/Common/ArchiveExtractCallback.cpp`

**Finding the Changes**:

```bash
# Clone 7-Zip source
git clone https://github.com/ip7z/7zip.git
cd 7zip

# Find the 25.00 release commit
git log --oneline --all --grep="25.00" | head -1
# 3951499 25.00
git tag | grep "24\|25"

# Compare versions (if tags exist)
git diff 24.09..25.00 -- CPP/7zip/UI/Common/ArchiveExtractCallback.cpp > 7zip_patch.diff

# Or download releases and use diff
#wget https://github.com/ip7z/7zip/archive/refs/tags/24.09.tar.gz
#wget https://github.com/ip7z/7zip/archive/refs/tags/25.00.tar.gz
#tar -xzf 24.09.tar.gz && tar -xzf 25.00.tar.gz
#diff -u 7zip-24.09/CPP/7zip/UI/Common/ArchiveExtractCallback.cpp \
#        7zip-25.00/CPP/7zip/UI/Common/ArchiveExtractCallback.cpp > 7zip_patch.diff

# Review the diff
less 7zip_patch.diff
```

**Key Changes Identified**:

**1. IsSafePath Function Signature Changed**:

```cpp
// BEFORE (vulnerable):
bool IsSafePath(const UString &path)
{
  CLinkLevelsInfo levelsInfo;
  levelsInfo.Parse(path);
  return !levelsInfo.IsAbsolute
      && levelsInfo.LowLevel >= 0
      && levelsInfo.FinalLevel > 0;
}

// AFTER (patched):
static bool IsSafePath(const UString &path, bool isWSL)
{
  CLinkLevelsInfo levelsInfo;
  levelsInfo.Parse(path, isWSL);  // Now takes isWSL parameter
  return !levelsInfo.IsAbsolute
      && levelsInfo.LowLevel >= 0
      && levelsInfo.FinalLevel > 0;
}

// Wrapper for backward compatibility
bool IsSafePath(const UString &path)
{
  return IsSafePath(path, false); // isWSL
}
```

**2. CLinkLevelsInfo::Parse Modified**:

```cpp
// BEFORE:
void CLinkLevelsInfo::Parse(const UString &path)
{
  IsAbsolute = NName::IsAbsolutePath(path);
  LowLevel = 0;
  FinalLevel = 0;
  // ... parsing logic ...
}

// AFTER:
void CLinkLevelsInfo::Parse(const UString &path, bool isWSL)
{
  // NEW: Different absolute path detection for WSL/Linux symlinks
  IsAbsolute = isWSL ? IS_PATH_SEPAR(path[0]) : NName::IsAbsolutePath(path);
  LowLevel = 0;
  FinalLevel = 0;
  // ... parsing logic ...
}
```

**3. Dangerous Link Check Enhanced**:

```cpp
// BEFORE: Windows-only directory check, no WSL awareness
if (!_ntOptions.SymLinks_AllowDangerous.Val)
{
    #ifdef _WIN32
    if (_item.IsDir)  // BUG: Only checked dirs on Windows!
    #endif
    if (linkInfo.isRelative)
      {
        CLinkLevelsInfo levelsInfo;
        levelsInfo.Parse(linkInfo.linkPath);  // No WSL parameter!
        if (levelsInfo.FinalLevel < 1 || levelsInfo.IsAbsolute)
          return SendMessageError2(...);
      }
}

// AFTER: All relative links checked with WSL awareness
if (!_ntOptions.SymLinks_AllowDangerous.Val && link.isRelative)
{
    CLinkLevelsInfo levelsInfo;
    levelsInfo.Parse(link.LinkPath, link.Is_WSL());  // NEW: WSL-aware parsing
    if (levelsInfo.FinalLevel < 1 || levelsInfo.IsAbsolute)
      return SendMessageError2(...);
}
```

**4. New Normalization Functions Added**:

```cpp
// NEW: Removes absolute path prefixes and normalizes link paths
void CLinkInfo::Remove_AbsPathPrefixes()
{
  while (!LinkPath.IsEmpty())
  {
    unsigned n = 0;
    if (!Is_WSL())
      n = NName::GetRootPrefixSize(LinkPath);  // Detects C:\, \\, etc.
    if (n == 0 && IS_PATH_SEPAR(LinkPath[0]))
      n = 1;
    if (n == 0)
      break;
    isRelative = false;  // Mark as was-absolute
    LinkPath.DeleteFrontal(n);
  }
}

// NEW: Main normalization entry point
void CLinkInfo::Normalize_to_RelativeSafe(UStringVector &removePathParts)
{
  RemoveRedundantPathSeparators(LinkPath);
  Remove_AbsPathPrefixes();
  // ... handle removePathParts prefix stripping ...
}
```

**5. Link Type Refactoring**:

```cpp
// BEFORE: Boolean flags
bool isHardLink;
bool isJunction;
bool isWSL;
UString linkPath;

// AFTER: Enum-based type system
enum { k_LinkType_HardLink, k_LinkType_PureSymLink, k_LinkType_Junction, k_LinkType_WSL };
unsigned LinkType;
bool isWindowsPath;  // NEW: Track if path uses Windows semantics
UString LinkPath;

// NEW: Type query methods
bool Is_WSL() const { return LinkType == k_LinkType_WSL; }
bool Is_HardLink() const { return LinkType == k_LinkType_HardLink; }
bool Is_AnySymLink() const { return LinkType != k_LinkType_HardLink; }
```

**6. Slash Conversion Macro**:

```cpp
// NEW: Convert Linux paths to system paths early in processing
#if WCHAR_PATH_SEPARATOR != L'/'
  #define REPLACE_SLASHES_from_Linux_to_Sys(s) \
    { NArchive::NItemName::ReplaceToWinSlashes(s, true); }
#else
  #define REPLACE_SLASHES_from_Linux_to_Sys(s)
#endif

// Applied in ReadLink():
if (!_link.LinkPath.IsEmpty())
  REPLACE_SLASHES_from_Linux_to_Sys(_link.LinkPath)
```

#### Root Cause Analysis

**The Logic Bug**:

1. **WSL/Linux Symlinks on Windows**: Archives (tar, rar5, etc.) can contain Linux-style symlinks. When extracted on Windows, these symlinks could point to Windows-style absolute paths (e.g., `C:\Windows\System32\`).

2. **Missing WSL-Aware Path Detection**:
   - `CLinkLevelsInfo::Parse()` always used `NName::IsAbsolutePath()` which uses Windows logic
   - For WSL symlinks, `/etc/passwd` was correctly detected as absolute
   - But a WSL symlink containing `C:\Users\...` was NOT detected as absolute because WSL paths expect `/` as absolute indicator

3. **Conditional Dangerous Link Check**:
   - The `SymLinks_AllowDangerous` validation had `#ifdef _WIN32` and `if (_item.IsDir)` guards
   - On Windows, only directory symlinks were validated
   - File symlinks bypassed the dangerous link check entirely

4. **No Path Normalization**:
   - Absolute paths in archives were passed directly to symlink creation
   - No stripping of `\??\`, `\\?\UNC\`, or drive letter prefixes
   - Result: Symlinks could point outside the extraction directory

5. **Late Slash Conversion**:
   - Linux separators (`/`) were converted to Windows separators (`\`) too late in the process
   - Path validation occurred before normalization in some code paths

**Attack Scenario**:

```text
Archive structure (tar/rar5 with Linux-style symlinks):
├── safe_folder/
├── safe_folder/link -> /??/C:/Users/Public/Desktop  (or C:\Users\Public\Desktop)
└── safe_folder/link/malware.exe

Extraction on Windows (vulnerable 7-Zip 24.09):
1. ReadLink() reads symlink target: "C:\Users\Public\Desktop"
2. IsSafePath() called WITHOUT isWSL=true
3. NName::IsAbsolutePath("C:\Users\Public\Desktop") returns TRUE on Windows
   BUT for WSL symlink paths, the check used Linux semantics (looks for '/')
4. Path classified as "relative" - dangerous link check skipped for files
5. Symlink created: safe_folder\link -> C:\Users\Public\Desktop
6. File extraction: safe_folder\link\malware.exe
7. Windows follows symlink → writes to C:\Users\Public\Desktop\malware.exe

Result: Arbitrary file write outside extraction directory!
```

**How the Patch Fixes It**:

```text
Patched extraction (7-Zip 25.00):
1. ReadLink() reads symlink target, immediately converts slashes
2. REPLACE_SLASHES_from_Linux_to_Sys() normalizes path separators early
3. link.Normalize_to_RelativeSafe() called:
   - Remove_AbsPathPrefixes() strips C:\, \\?\, \??\ prefixes
   - isRelative set to false if any prefix removed
4. IsSafePath(path, link.Is_WSL()) - WSL-aware absolute path detection
5. Dangerous link check runs for ALL relative symlinks (no _item.IsDir guard)
6. CLinkLevelsInfo::Parse() uses correct semantics based on link type

Result: Malicious symlinks rejected with "Dangerous link path was ignored"
```

#### Practical Triage Checklist

**When Analyzing Path Validation Code**:

1. **Search for**:
   - `IsSafePath`, `ValidatePath`, `CheckPath`, `Normalize` functions
   - `IsAbsolute`, `IsRelative`, `GetRootPrefixSize` checks
   - Path concatenation: `JoinPath`, `CombinePath`, `operator/`, `+` on path strings
   - Symlink handling: `CreateSymbolicLink`, `SetReparseData`, `readlink`, `lstat`
   - Slash/separator conversion: `Replace('/', '\\')`, path separator macros

2. **Verify**:
   - Absolute path detection works across OS semantics (Linux `/`, Windows `C:\`, UNC `\\`, device paths `\??\`)
   - WSL/cross-platform symlinks handled with correct path semantics for their origin
   - Path normalization (prefix stripping, redundant separator removal) happens BEFORE validation
   - "Dangerous link" checks run for ALL symlink types (files AND directories)
   - No platform-specific guards (`#ifdef _WIN32`) that skip security checks

3. **Test Cases**:
   - Windows absolute in Linux/WSL symlink: `C:\...`, `\??\C:\...`
   - UNC paths in archives: `\\server\share`, `\\?\UNC\server\share`
   - Mixed separators: `C:\dir/subdir`, `/home\user`
   - Relative paths with `..` sequences: `../../../etc/passwd`
   - Symlinks to symlinks (chain validation)
   - Device paths: `\??\`, `\\?\`, `\\.\`
   - Path prefix attacks: `C:relative` (drive-relative), `\root` (root-relative)

#### Creating a Report

**Report Structure**:

````markdown
# Patch Diff Analysis: 7-Zip Symlink Path Traversal

|                |                         |
| -------------- | ----------------------- |
| **Researcher** | [Your Name / Handle]    |
| **Date**       | [Analysis Date]         |
| **Vendor**     | Igor Pavlov (7-Zip)     |
| **Product**    | 7-Zip File Archiver     |
| **Affected**   | 21.02 - 24.09 (Windows) |
| **Fixed**      | 25.00+                  |

## Executive Summary

7-Zip versions 21.02 through 24.09 contain path traversal vulnerabilities in symbolic
link handling during archive extraction. An attacker can craft a malicious archive that,
when extracted, writes files to arbitrary locations outside the intended directory.

**Severity**: High (CVSS 7.0)  
**Attack Vector**: Local (malicious archive)  
**User Interaction**: Required (victim must extract archive)  
**Privileges Required**: None (elevated privileges increase impact)

## Technical Analysis

### Affected Component

- **File**: `CPP/7zip/UI/Common/ArchiveExtractCallback.cpp`
- **Functions**: `IsSafePath()`, `CLinkLevelsInfo::Parse()`, `SetLink()`

### Root Cause

The vulnerability stems from two interrelated issues:

1. **Missing WSL Path Semantics**: `CLinkLevelsInfo::Parse()` used Windows-only absolute
   path detection. Linux/WSL symlinks containing Windows paths (e.g., `C:\Users\...`)
   were incorrectly classified as relative paths.

2. **Conditional Security Check**: The dangerous symlink validation was guarded by
   `#ifdef _WIN32` and `if (_item.IsDir)`, causing file symlinks to bypass validation.

### Vulnerable Code Flow

<!-- Include relevant code snippets with before/after comparison -->

[See full diff: `git diff 24.09..25.00 -- CPP/7zip/UI/Common/ArchiveExtractCallback.cpp`]

## Proof of Concept

### Attack Scenario

```
malicious.zip
├── innocent/
├── innocent/escape -> C:\Users\Public\Desktop   (symlink)
└── innocent/escape/payload.exe                   (malicious file)
```

### Exploitation Steps

1. Attacker creates archive with symlink pointing to absolute Windows path
2. Victim extracts archive using 7-Zip ≤24.09
3. Symlink passes validation (misclassified as relative)
4. Subsequent file writes follow symlink to attacker-controlled location
5. `payload.exe` written to `C:\Users\Public\Desktop\payload.exe`

### Impact

- **Arbitrary File Write**: Overwrite system files, plant executables
- **Code Execution**: Via DLL hijacking, startup folder, or file association abuse
- **Privilege Escalation**: If extraction runs with elevated privileges

## Patch Analysis

### Summary of Changes

| Function                           | Change                             | Security Impact                                  |
| ---------------------------------- | ---------------------------------- | ------------------------------------------------ |
| `CLinkLevelsInfo::Parse()`         | Added `isWSL` parameter            | Correct absolute path detection for WSL symlinks |
| `IsSafePath()`                     | Now WSL-aware                      | Prevents path classification bypass              |
| `SetLink()`                        | Removed `#ifdef`/`IsDir` guards    | All symlinks validated, not just directories     |
| New: `Normalize_to_RelativeSafe()` | Strips `C:\`, `\??\`, UNC prefixes | Defense-in-depth normalization                   |

### Patch Effectiveness

The patch addresses the root cause through multiple layers:

- WSL symlinks now correctly identified as absolute
- All symlink types (file/directory) validated
- Path prefixes stripped before validation

**Potential Bypasses**: None identified. Recommend testing edge cases:
UNC paths, mixed separators, drive-relative paths (`C:file`).

## Timeline

| Date       | Event                                                  |
| ---------- | ------------------------------------------------------ |
| 2025-07-05 | 7-Zip 25.00 released (silent fix)                      |
| 2025-08-03 | 7-Zip 25.01 released, CVE-2025-55188 mentioned         |
| 2025-10-07 | ZDI public disclosure (CVE-2025-11001, CVE-2025-11002) |
| [Date]     | This analysis completed                                |

## Recommendations

**Immediate**:

1. Upgrade to 7-Zip 25.01 or later
2. Use `-snld20` switch only if legacy symlink behavior explicitly required

**Organizational**:

3. Audit automated extraction workflows for symlink handling
4. Consider sandboxing archive extraction (e.g., containers, restricted directories)
5. Scan incoming archives for suspicious symlink targets

## References

- 7-Zip Source: https://github.com/ip7z/7zip
- 7-Zip History: https://www.7-zip.org/history.txt
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
````

### Practical Exercise

**Task**: Write a patch diff report for a source-available vulnerability

1. **Choose a Target** (suggestions):
   - **7-Zip**: Diff 24.09 vs 25.00 for symlink vulnerabilities (CVE-2025-11001/11002)
   - **curl**: Check recent CVEs at https://curl.se/docs/security.html
   - **OpenSSL**: https://www.openssl.org/news/vulnerabilities.html
   - **nginx**: Security advisories at https://nginx.org/en/security_advisories.html

2. **Perform Analysis**:

   ```bash
   git clone <repo> && cd <repo>
   git diff <vuln_tag>..<patched_tag> -- <file> > patch.diff
   # Identify: What was added? What was removed? Why?
   ```

3. **Write Report**: Use template above, focus on:
   - Clear root cause explanation (1-2 sentences)
   - Patch summary table (what changed, why)
   - Actionable recommendations

4. **Self-Review Checklist**:
   - CVE/version numbers verified against official sources
   - Root cause explains the programmer's mistake
   - Patch changes mapped to vulnerability fixes
   - Recommendations are specific and actionable

**Success Criteria**:

- Accurate CVE/version information (cross-check with vendor advisories)
- Root cause explains WHY the bug existed, not just WHAT changed
- Report readable by someone unfamiliar with the codebase

### Key Takeaways

1. **Cross-platform code has cross-platform bugs**: WSL symlinks exposed path semantics mismatch between Linux and Windows
2. **Conditional compilation hides attack surface**: `#ifdef _WIN32` guards can create platform-specific vulnerabilities
3. **"Defense in depth" patches are common**: 7-Zip added multiple checks (WSL detection, prefix stripping, separator normalization)
4. **Silent fixes get CVEs later**: 25.00 fixed the bug (July 2025); ZDI disclosed CVE-2025-11001/11002 in October 2025
5. **Source diffing reveals intent**: Seeing `Normalize_to_RelativeSafe()` added explains the fix strategy better than binary diff alone

### Discussion Questions

1. The 7-Zip fix added 6+ distinct changes. How do you determine which change fixes the core vulnerability vs. adds defense-in-depth?
2. CVE-2025-11001/11002 were disclosed by ZDI months after 25.00 shipped. What are the pros/cons of "silent" security fixes?
3. The vulnerability required symlinks AND file extraction through them. How does attack chain complexity affect severity ratings?
4. 7-Zip 25.01 added `-snld20` to bypass the new checks. When are "escape hatches" for security features appropriate?

## Day 7: Capstone Project - The Patch Diffing Campaign

- **Goal**: Apply the week's techniques to analyze a real-world vulnerability end-to-end, from binary acquisition to professional reporting.
- **Activities**:
  - **Select a Target**: Choose from the suggested CVEs below or find your own recent security patch.
  - **Execution**: Complete the full pipeline: acquire → extract → diff → analyze → report.
  - **Analysis**: Identify changed functions, understand root cause, correlate with public documentation.
  - **Reporting**: Create a comprehensive vulnerability report suitable for disclosure.

### Suggested Capstone Targets

Choose ONE of the following based on your interest and available environment:

**Option A: Windows - CVE-2024-38063 (tcpip.sys IPv6 RCE)**

- **Component**: `tcpip.sys` (Windows TCP/IP driver)
- **Type**: Remote Code Execution via IPv6 packets
- **CVSS**: 9.8 (Critical)
- **Patch**: August 2024 (KB5041571)
- **Why This One**: More recent than EvilESP, similar component, well-documented
- **Resources**:
  - [MSRC Advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38063)
  - [Critical Analysis of CVE-2024-38063: The Microsoft IPv6-Vulnerability](https://www.db-thueringen.de/servlets/MCRFileNodeServlet/dbt_derivate_00068871/ilm1-202520021_005-008.pdf)

**Option B: Windows - CVE-2024-21338 (appid.sys LPE)**

- **Component**: `appid.sys` (AppLocker driver)
- **Type**: Local Privilege Escalation
- **CVSS**: 7.8 (High)
- **Patch**: February 2024
- **Why This One**: Kernel driver, smaller than tcpip.sys, good for learning
- **Resources**:
  - [Avast Analysis](https://www.gendigital.com/blog/insights/research/lazarus-and-the-fudmodule-rootkit-beyond-byovd-with-an-admin-to-kernel-zero-day)

**Option C: Linux - CVE-2024-1086 (nf_tables LPE)**

- **Component**: `nf_tables` (Netfilter subsystem)
- **Type**: Use-After-Free leading to LPE
- **CVSS**: 7.8 (High)
- **Patch**: Linux 6.8+
- **Why This One**: Excellent public write-ups, source available, affects most distros
- **Resources**:
  - [Notselwyn's Write-up](https://pwning.tech/nftables/)
  - [PoC on GitHub](https://github.com/Notselwyn/CVE-2024-1086)

**Option D: Application - CVE-2024-4367 (PDF.js Type Confusion)**

- **Component**: Mozilla PDF.js (Firefox built-in PDF reader)
- **Type**: Type confusion leading to code execution
- **CVSS**: 8.8 (High)
- **Patch**: Firefox 126+
- **Why This One**: JavaScript-based, source diffing, affects browsers
- **Resources**:
  - [Codean Labs Analysis](https://codeanlabs.com/blog/research/cve-2024-4367-arbitrary-js-execution-in-pdf-js/)

### Capstone Execution Framework

#### Phase 1: Target Selection and Research

```bash
# Create project directory
mkdir -p ~/capstone/CVE-YYYY-XXXXX/{vulnerable,patched,symbols,analysis,report}
cd ~/capstone/CVE-YYYY-XXXXX

# Research the CVE
# - Read MSRC/NVD advisory
# - Find affected versions
# - Identify specific binaries/modules
# - Note the patch KB number or commit hash
```

**Document your findings**:

```markdown
# Capstone Research Notes

## CVE Information

- CVE ID: CVE-YYYY-XXXXX
- Component: [binary name]
- Vulnerable Version: [version]
- Patched Version: [version]
- Patch Reference: [KB number or commit]

## Initial Hypotheses

- Expected bug class: [overflow/UAF/logic/etc.]
- Expected location: [subsystem/function if known]
- Expected fix: [bounds check/null check/etc.]
```

#### Phase 2: Binary Acquisition

**For Windows targets**:

```bash
# Method 1: WinbIndex (preferred)
# Visit https://winbindex.m417z.com/
# Search for your binary, download both versions

# Method 2: Extract from Windows Update
# Download .msu from Microsoft Update Catalog
# Use extraction scripts from Day 1

# Method 3: Use your Day 4 automation scripts
# - Use Extract-Patch.ps1 from Day 1 to download binaries for both KB versions
# - Use ghidriff_batch.py from Day 4 for automated batch diffing
# - Scripts are in C:\patch-analysis\scripts\ (from Day 4 setup)
```

**For Linux targets**:

```bash
# Follow Day 5 "Linux Kernel Patch Diffing Workflow" (Steps 1-6)
# - Step 1-2: Download kernel images and debug symbols (apt-get download, ddebs repo)
# - Step 3: Extract vmlinux from dbgsym packages or vmlinuz
# - Step 4: Identify changed modules with diff -qr
# - Step 5-6: Use ghidriff on specific .ko modules or use git diff for source-level analysis
```

#### Phase 3: Binary Diffing

```bash
# Use ghidriff as learned in Day 2 (see "Ghidriff Workflow" section)
# Key options: --max-section-funcs, --max-ram-percent, --symbols-path
# For large binaries (ntoskrnl.exe, tcpip.sys): use --section .text or increase limits
# Output includes: .ghidriff.md (report), .ghidriff.json (for automation)

# Alternative: Use Ghidra's built-in Version Tracking (Day 2, Step 0-5)
# - Better for interactive analysis and side-by-side comparison
```

**Diff Analysis Checklist**:

- How many functions changed? (Targeted patch = few changes)
- What are the function names? (Security-relevant names?)
- What was added? (Validation, bounds checks, error handling?)
- What was removed? (Dead code, vulnerable paths?)
- Any new functions introduced? (Sanitization helpers?)

#### Phase 4: Root Cause Analysis

**Deep dive into changed functions**:

```bash
# Load both versions in Ghidra for side-by-side comparison
# Tools → Version Tracking → Create Session

# Focus on the function with lowest similarity score
# Examine:
# 1. What data flows into this function?
# 2. What validation was missing?
# 3. How does the patch fix it?
```

**Reconstruct the vulnerability**:

```markdown
## Root Cause Analysis

### Vulnerable Code Path

1. [Entry point] receives user data
2. [Function A] passes data to [Function B] without validation
3. [Function B] uses data in [dangerous operation]
4. Result: [overflow/UAF/etc.]

### The Fix

- Added check: `if (size > MAX_SIZE) return ERROR;`
- Location: [Function B], line [X]
- Effect: Prevents [dangerous condition]

### Why This Bug Existed

- [Missing bounds check / incorrect assumption / race condition / etc.]
- [Complexity of code path made it easy to miss]
```

#### Phase 5: Exploitation Assessment

**Determine exploitability**:

```markdown
## Exploitation Assessment

### Primitive Analysis

- Type: [read/write/execute primitive]
- Control: [What can attacker control?]
- Constraints: [Size limits, character restrictions, alignment]

### Attack Surface

- Local vs Remote: [Can be triggered remotely?]
- Authentication: [Required? What level?]
- User Interaction: [Required?]

### Mitigations

- ASLR: [Applies? Bypassable?]
- DEP/NX: [Applies?]
- CFG/CET: [Applies?]
- Stack Canaries: [Applies?]

### Exploitability Verdict

- [ ] EXPLOITABLE - Direct path to code execution
- [ ] PROBABLY_EXPLOITABLE - Requires additional primitives
- [ ] PROBABLY_NOT_EXPLOITABLE - DoS only or mitigations block
- [ ] NOT_EXPLOITABLE - Cannot reach vulnerable code
```

#### Phase 6: Report Writing

Use the template from Day 6 to create your final report:

```markdown
# Patch Diff Analysis: [CVE-ID]

## Executive Summary

[2-3 sentences summarizing the vulnerability, impact, and fix]

## Vulnerability Details

### Component

### Root Cause

### Attack Vector

## Technical Analysis

### Diff Summary

### Changed Functions

### Code Comparison

[Include decompiled code snippets]

## Exploitation Assessment

### Primitive

### Constraints

### Mitigations

## Patch Analysis

### Fix Description

### Effectiveness

### Potential Bypasses

## Recommendations

### Immediate Actions

### Long-term Mitigations

## References

## Timeline

## Author
```

### Capstone Deliverables Checklist

**Required Deliverables**:

- `research_notes.md` - Initial CVE research and hypotheses
- `vulnerable/` and `patched/` directories with binaries
- `analysis/diff_report/` - Ghidriff output
- `report/patch_diff_report.md` - Professional vulnerability report
- `report/screenshots/` - Key diff screenshots

**Grading Rubric** (Self-Assessment):

| Criterion                 | Points  | Description                                |
| ------------------------- | ------- | ------------------------------------------ |
| Binary Acquisition        | 15      | Both versions obtained, organized          |
| Diff Execution            | 15      | Ghidriff ran successfully, output reviewed |
| Root Cause Identification | 25      | Correctly identified the vulnerability     |
| Patch Understanding       | 20      | Explained what the patch does and why      |
| Exploitation Assessment   | 15      | Realistic assessment of exploitability     |
| Report Quality            | 10      | Clear, professional, actionable            |
| **Total**                 | **100** |                                            |

### Common Capstone Pitfalls

**Avoid These Mistakes**:

1. **Picking a CVE without public details**
   - Some CVEs have no write-ups; you'll struggle without context
   - Prefer CVEs with at least an advisory or blog post

2. **Ignoring compiler noise**
   - Many "changed" functions are just recompilation artifacts
   - Focus on functions with < 0.95 similarity AND security-relevant names

3. **Missing the forest for the trees**
   - Don't get lost in assembly details
   - Step back and ask: "What was the programmer's mistake?"

4. **Incomplete exploitation assessment**
   - "It crashes" is not an assessment
   - Explain: What can an attacker control? What's the primitive?

5. **Report without remediation**
   - Always include actionable recommendations
   - "Upgrade to version X" is the minimum

### Key Takeaways

1. **Diffing is iterative**: You rarely find the bug in the first pass. Filter noise, ignore compiler optimizations, and focus on logic changes.
2. **Context is king**: A changed line means nothing without understanding the surrounding function and data flow.
3. **Symbols are essential**: Without PDBs or debug symbols, diffing is significantly harder. Always prioritize obtaining them.
4. **Reporting matters**: A good finding is useless if you can't communicate the impact and root cause clearly.
5. **Practice makes perfect**: Each CVE you analyze builds pattern recognition for the next one.

### Discussion Questions

1. How does the choice of CVE affect the difficulty of patch diffing?
2. What strategies help when a patch changes hundreds of functions?
3. Why might a vendor's patch introduce new vulnerabilities?
4. How would you approach diffing a browser update with thousands of changes?

### Looking Ahead to Week 4

You've found the bug in the patch. But is it exploitable? Can you actually reach the vulnerable code from user input? Next week, we answer these questions. You'll learn WinDbg and GDB, learn to triage thousands of crashes down to a handful of unique bugs, and trace exactly how attacker-controlled data reaches the vulnerable function. By week's end, you'll turn fuzzer crashes and patch-diff findings into PoC scripts.

<!-- Written by AnotherOne from @Pwn3rzs Telegram channel -->

