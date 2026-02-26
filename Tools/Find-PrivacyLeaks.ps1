param(
    [switch]$Staged,
    [switch]$AllTracked,
    [string]$CommitRange = "",
    [switch]$MetadataOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if (-not $Staged -and -not $AllTracked -and -not $MetadataOnly) {
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

$forbiddenPathRules = @(
    @{
        Id = "SEC-400"
        Description = "Secrets directory should never be tracked"
        Pattern = '^secrets/'
    },
    @{
        Id = "SEC-401"
        Description = "Private key file path should never be tracked"
        Pattern = '(?i)(^|/)(?:id_rsa(?:\.pub)?|.*private.*\.(?:xml|pem|key|pfx))$'
    }
)

$allowedGitEmails = @(
    "96605631+alexphillips-dev@users.noreply.github.com",
    "noreply@github.com",
    "41898282+github-actions[bot]@users.noreply.github.com"
)

if (-not [string]::IsNullOrWhiteSpace([string]$env:TAG_ALLOWED_GIT_EMAILS)) {
    foreach ($item in @(([string]$env:TAG_ALLOWED_GIT_EMAILS).Split(",", [System.StringSplitOptions]::RemoveEmptyEntries))) {
        $email = $item.Trim().ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($email)) { continue }
        if ($allowedGitEmails -notcontains $email) {
            $allowedGitEmails += $email
        }
    }
}

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

function Normalize-Email([string]$emailValue) {
    $value = [string]$emailValue
    if ([string]::IsNullOrWhiteSpace($value)) { return "" }
    $value = $value.Trim()
    if ($value.StartsWith("<") -and $value.EndsWith(">") -and $value.Length -ge 3) {
        $value = $value.Substring(1, $value.Length - 2)
    }
    return $value.Trim().ToLowerInvariant()
}

function Get-GitConfigValue([string]$key) {
    try {
        return [string](& git -C $repoRoot config --get $key 2>$null)
    } catch {
        return ""
    }
}

function Get-CommitMetadataRecords([string]$range) {
    $args = @("log", "--format=%H%x1f%ae%x1f%ce")
    if ([string]::IsNullOrWhiteSpace($range)) {
        $args += "--all"
    } else {
        $args += $range
    }
    $rows = @()
    try {
        $rows = @(& git -C $repoRoot @args 2>$null)
    } catch {
        $rows = @()
    }

    $records = @()
    foreach ($row in $rows) {
        if ([string]::IsNullOrWhiteSpace([string]$row)) { continue }
        $parts = ([string]$row).Split([char]0x1f)
        if ($parts.Count -lt 3) { continue }
        $records += [pscustomobject]@{
            Commit = [string]$parts[0]
            AuthorEmail = Normalize-Email([string]$parts[1])
            CommitterEmail = Normalize-Email([string]$parts[2])
        }
    }
    return @($records)
}

function Get-TagMetadataRecords {
    $rows = @()
    try {
        $rows = @(& git -C $repoRoot for-each-ref refs/tags "--format=%(refname:short)%x1f%(taggeremail)" 2>$null)
    } catch {
        $rows = @()
    }
    $records = @()
    foreach ($row in $rows) {
        if ([string]::IsNullOrWhiteSpace([string]$row)) { continue }
        $parts = ([string]$row).Split([char]0x1f)
        if ($parts.Count -lt 2) { continue }
        $records += [pscustomobject]@{
            Tag = [string]$parts[0]
            TaggerEmail = Normalize-Email([string]$parts[1])
        }
    }
    return @($records)
}

function Add-Finding {
    param(
        [System.Collections.Generic.List[object]]$Sink,
        [Parameter(Mandatory = $true)][string]$Rule,
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)][string]$File,
        [int]$Line = 0,
        [string]$Snippet = ""
    )
    $Sink.Add([pscustomobject]@{
        Rule = $Rule
        Description = $Description
        File = $File
        Line = $Line
        Snippet = $Snippet
    }) | Out-Null
}

$findings = New-Object System.Collections.Generic.List[object]

$candidatePaths = @(Get-ScanTargetPaths -Staged:$Staged -AllTracked:$AllTracked)

# Content + path scan
if (-not $MetadataOnly) {
    if ($candidatePaths.Count -eq 0) {
        Write-Host "[privacy-scan] No files to scan."
    } else {
        $scanFiles = @()
        foreach ($relativePath in $candidatePaths) {
            if ([string]::IsNullOrWhiteSpace($relativePath)) {
                continue
            }
            if (Test-IsExcludedFile -RelativePath $relativePath) {
                continue
            }

            foreach ($pathRule in $forbiddenPathRules) {
                if ([string]$relativePath -match [string]$pathRule.Pattern) {
                    Add-Finding -Sink $findings -Rule ([string]$pathRule.Id) -Description ([string]$pathRule.Description) -File ([string]$relativePath) -Line 0 -Snippet ([string]$relativePath)
                }
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
                        Add-Finding -Sink $findings -Rule ([string]$rule.Id) -Description ([string]$rule.Description) -File ([string]$file.RelativePath) -Line $lineNumber -Snippet $snippet
                    }
                }
            }
        }

        if ($scanFiles.Count -eq 0) {
            Write-Host "[privacy-scan] No eligible text files to scan."
        }
    }
}

# Metadata scan (always on)
$configuredEmail = Normalize-Email (Get-GitConfigValue -key "user.email")
if ([string]::IsNullOrWhiteSpace($configuredEmail)) {
    Add-Finding -Sink $findings -Rule "META-300" -Description "git config user.email is not set" -File "git-config" -Line 0 -Snippet "user.email=<empty>"
} elseif ($allowedGitEmails -notcontains $configuredEmail) {
    Add-Finding -Sink $findings -Rule "META-301" -Description "git config user.email is not on the allowlist" -File "git-config" -Line 0 -Snippet ("user.email={0}" -f $configuredEmail)
}

$useConfigOnly = Normalize-Email (Get-GitConfigValue -key "user.useConfigOnly")
if ($useConfigOnly -ne "true") {
    Add-Finding -Sink $findings -Rule "META-302" -Description "git config user.useConfigOnly should be true" -File "git-config" -Line 0 -Snippet ("user.useConfigOnly={0}" -f $useConfigOnly)
}

$metadataScope = if ([string]::IsNullOrWhiteSpace($CommitRange)) { "all-history" } else { $CommitRange }
$commitRecords = @(Get-CommitMetadataRecords -range $CommitRange)
foreach ($record in $commitRecords) {
    if (-not [string]::IsNullOrWhiteSpace([string]$record.AuthorEmail) -and ($allowedGitEmails -notcontains [string]$record.AuthorEmail)) {
        Add-Finding -Sink $findings -Rule "META-310" -Description "Commit author email is not on allowlist" -File ([string]$record.Commit) -Line 0 -Snippet ("author={0}" -f [string]$record.AuthorEmail)
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$record.CommitterEmail) -and ($allowedGitEmails -notcontains [string]$record.CommitterEmail)) {
        Add-Finding -Sink $findings -Rule "META-311" -Description "Commit committer email is not on allowlist" -File ([string]$record.Commit) -Line 0 -Snippet ("committer={0}" -f [string]$record.CommitterEmail)
    }
}

foreach ($tag in @(Get-TagMetadataRecords)) {
    if ([string]::IsNullOrWhiteSpace([string]$tag.TaggerEmail)) { continue }
    if ($allowedGitEmails -notcontains [string]$tag.TaggerEmail) {
        Add-Finding -Sink $findings -Rule "META-320" -Description "Tagger email is not on allowlist" -File ("tag:{0}" -f [string]$tag.Tag) -Line 0 -Snippet ("tagger={0}" -f [string]$tag.TaggerEmail)
    }
}

if ($findings.Count -gt 0) {
    Write-Host "[privacy-scan] Potential privacy/security leaks found:"
    foreach ($finding in $findings) {
        if ([int]$finding.Line -gt 0) {
            Write-Host ("  [{0}] {1}:{2} {3}" -f $finding.Rule, $finding.File, $finding.Line, $finding.Description)
        } else {
            Write-Host ("  [{0}] {1} {2}" -f $finding.Rule, $finding.File, $finding.Description)
        }
        Write-Host ("       {0}" -f $finding.Snippet)
    }
    throw ("Privacy/security scan failed with {0} finding(s)." -f $findings.Count)
}

if ($MetadataOnly) {
    Write-Host ("[privacy-scan] Metadata scan passed. Scope: {0}" -f $metadataScope)
} else {
    $checked = if ($candidatePaths) { $candidatePaths.Count } else { 0 }
    Write-Host ("[privacy-scan] Scan passed. Files checked: {0}. Metadata scope: {1}" -f $checked, $metadataScope)
}
