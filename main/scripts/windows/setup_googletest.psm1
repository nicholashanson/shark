$globalVars = Join-Path $PSScriptRoot "global_vars.psm1"
Import-Module $globalVars

function Build-WithMinGW {
    param (
        [string]$buildDir
    )

    # Build GoogleTest with G++
    Write-Host "Building GoogleTest with MinGW..."
    try {
        # Ensure the build directory exists
        if (-not (Test-Path $buildDir)) {
            New-Item -Path $buildDir -ItemType Directory | Out-Null
        }
        Push-Location $buildDir

        # Set the CMake generator to MinGW Makefiles
        $env:CC = "gcc"
        $env:CXX = "g++"

        # Run CMake with the MinGW Makefiles generator
        cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
        mingw32-make
        Pop-Location
        Write-Host "Successfully built GoogleTest with MinGW."
    } catch {
        Write-Host "Failed to build GoogleTest with MinGW. Exiting."
        exit 1
    }
}

function Setup-Googletest {
    param (
        [string]$scriptRoot,
        [string]$url = "https://github.com/google/googletest/archive/refs/heads/main.zip"
    )

    Write-Host "Received script root in function: $scriptRoot"

    if (-not (Test-Path $includeDir)) {
        Write-Host "$includeDir does not exist!"
    }

    $libDir = Join-Path $scriptRoot "..\lib"

    $gccPath = (Get-Command gcc).Source
    $gppPath = (Get-Command g++).Source

    Write-Host "gcc found at $gccPath"
    Write-Host "g++ found at $gppPath"

    Write-Host "Identified $includeDir"

    $zipFullPath = Join-Path $includeDir "googletest-main.zip"
    $googletestRootDir = Join-Path $includeDir "googletest-main"

    # build directory for G++ build
    $minGWBuildDir = Join-Path $googletestRootDir "build_mingw"

    # Ensure both lib directories exist
    if (-not (Test-Path $libDir)) {
        New-Item -Path $libDir -ItemType Directory | Out-Null
    }

    # Check if the gtest libraries already exist in ../lib relative to the script
    if ((Test-Path (Join-Path $libDir "libgtest.a")) -and 
        (Test-Path (Join-Path $libDir "libgtest_main.a")) ) {
        Write-Host "gtest libraries already exist. Skipping download and build."
        return
    }

    # Download GoogleTest if not already downloaded
    if (-not (Test-Path $zipFullPath)) {
        Write-Host "Downloading GoogleTest library to $zipFullPath ..."
        try {
            Invoke-WebRequest -Uri $url -OutFile $zipFullPath
            Write-Host "Successfully downloaded GoogleTest."
        } catch {
            Write-Host "Failed to download GoogleTest. Exiting."
            exit 1
        }
    } else {
        Write-Host "GoogleTest zip already exists. Skipping download."
    }

    # Extract GoogleTest
    if (-not (Test-Path $googletestRootDir)) {
        Write-Host "Extracting GoogleTest..."
        try {
            Expand-Archive -Path $zipFullPath -DestinationPath $includeDir -Force
            Write-Host "Successfully extracted GoogleTest."
        } catch {
            Write-Host "Failed to extract GoogleTest. Exiting."
            exit 1
        }
    } else {
        Write-Host "GoogleTest source already exists. Skipping extraction."
    }

    Build-WithMinGW -buildDir $minGWBuildDir

    # Copy G++ libraries to libs directory
    Write-Host "Copying G++ libraries to $libDir..."
    try {
        $gppBuiltLibs = Get-ChildItem -Path (Join-Path $minGWBuildDir "lib") -Filter "*.a"
        foreach ($lib in $gppBuiltLibs) {
            Copy-Item -Path $lib.FullName -Destination $libDir -Force
        }
        Write-Host "Successfully copied G++ libraries."
    } catch {
        Write-Host "Failed to copy G++ libraries. Exiting."
        exit 1
    }

    $gtestIncludeSource = Join-Path $googletestRootDir "googletest\include"
    if (Test-Path $gtestIncludeSource) {
        Write-Host "Copying GoogleTest headers from $gtestIncludeSource to $includeDir..."
        Copy-Item -Recurse -Force -Path "$gtestIncludeSource\*" -Destination $includeDir
        Write-Host "Successfully copied GoogleTest headers."
    } else {
        Write-Host "GoogleTest include directory not found. Skipping header copy."
    }

    Write-Host "Cleaning up extracted files..."
    Remove-Item $zipFullPath -Force
    Remove-Item $googletestRootDir -Recurse -Force

    Write-Host "GoogleTest setup complete."
}
