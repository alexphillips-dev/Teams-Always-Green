param(
    [switch]$Staged,
    [switch]$AllTracked
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if (-not $Staged -and -not $AllTracked) {
    $AllTracked = $true
}

$excludeRelativePaths = @(
    "Tools/Find-PrivacyLeaks.ps1"
)

$skipExtensions = @(
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".tiff", ".webp",
    ".zip", ".7z", ".rar", ".tar", ".gz",
    ".dll", ".exe", ".pdb", ".bin", ".pdf", ".woff", ".woff2"
)

$rules = @(
    @{
        Id = "PRIV-100"
        Description = "Absolute Windows user profile path"
        Pattern = 'C:\\Users\\[^\\\r\n]+'
    },
    @{
        Id = "PRIV-101"
        Description = "OneDrive organization path"
        Pattern = 'OneDrive - [^\\\r\n]+'
    },
    @{
        Id = "SEC-200"
        Description = "GitHub classic personal access token"
        Pattern = 'ghp_[A-Za-z0-9]{36}'
    },
    @{
        Id = "SEC-201"
        Description = "GitHub fine-grained personal access token"
        Pattern = 'github_pat_[A-Za-z0-9_]{82,}'
    },
    @{
        Id = "SEC-202"
        Description = "AWS access key id"
        Pattern = '\bAKIA[0-9A-Z]{16}\b'
    },
    @{
        Id = "SEC-203"
        Description = "Private key block"
        Pattern = '-----BEGIN (?:RSA|DSA|EC|OPENSSH|PRIVATE KEY)-----'
    }
)

function Test-IsExcludedFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    foreach ($item in $excludeRelativePaths) {
        if ($RelativePath -ieq $item) {
            return $true
        }
    }
    return $false
}

function Get-ScanTargetPaths {
    param(
        [switch]$Staged,
        [switch]$AllTracked
    )

    if ($Staged) {
        return @(git -C $repoRoot diff --cached --name-only --diff-filter=ACMR)
    }
    if ($AllTracked) {
        return @(git -C $repoRoot ls-files)
    }
    return @()
}

$candidatePaths = @(Get-ScanTargetPaths -Staged:$Staged -AllTracked:$AllTracked)

if ($candidatePaths.Count -eq 0) {
    Write-Host "[privacy-scan] No files to scan."
    return
}

$scanFiles = @()
foreach ($relativePath in $candidatePaths) {
    if ([string]::IsNullOrWhiteSpace($relativePath)) {
        continue
    }
    if (Test-IsExcludedFile -RelativePath $relativePath) {
        continue
    }

    $extension = [System.IO.Path]::GetExtension($relativePath)
    if ($extension -and ($skipExtensions -contains $extension.ToLowerInvariant())) {
        continue
    }

    $absolutePath = Join-Path $repoRoot $relativePath
    if (-not (Test-Path -LiteralPath $absolutePath -PathType Leaf)) {
        continue
    }

    $scanFiles += [pscustomobject]@{
        RelativePath = $relativePath
        AbsolutePath = $absolutePath
    }
}

if ($scanFiles.Count -eq 0) {
    Write-Host "[privacy-scan] No eligible text files to scan."
    return
}

$findings = @()
foreach ($file in $scanFiles) {
    $lineNumber = 0
    foreach ($line in [System.IO.File]::ReadLines($file.AbsolutePath)) {
        $lineNumber++
        foreach ($rule in $rules) {
            if ($line -match $rule.Pattern) {
                $snippet = $line.Trim()
                if ($snippet.Length -gt 180) {
                    $snippet = $snippet.Substring(0, 180) + "..."
                }
                $findings += [pscustomobject]@{
                    Rule = $rule.Id
                    Description = $rule.Description
                    File = $file.RelativePath
                    Line = $lineNumber
                    Snippet = $snippet
                }
            }
        }
    }
}

if ($findings.Count -gt 0) {
    Write-Host "[privacy-scan] Potential privacy/security leaks found:"
    foreach ($finding in $findings) {
        Write-Host ("  [{0}] {1}:{2} {3}" -f $finding.Rule, $finding.File, $finding.Line, $finding.Description)
        Write-Host ("       {0}" -f $finding.Snippet)
    }
    throw ("Privacy/security scan failed with {0} finding(s)." -f $findings.Count)
}

Write-Host ("[privacy-scan] Scan passed. Files checked: {0}" -f $scanFiles.Count)
