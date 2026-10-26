<#
linkprotect-file-cleaner.ps1
pellis@cmitsolutions.com
2026.10.26.003

.SYNOPSIS
  Clean a DNS zone file for import:
    - Replace Barracuda LinkProtect URLs with original targets (handles nested wrapping)
    - Restore bare hostnames that LinkProtect turned into https:// links (with trailing dot)
    - Comment out SOA and NS records for import (handles multi-line SOA)
    - Strip 'http://' and 'https://' scheme prefixes from record data
      (comments and quoted TXT strings are left alone)
    - Preserves original line endings, tabs, and spacing

.PARAMETER InputPath
  Path to the input zone file. Required.

.PARAMETER OutputPath
  Optional. Path to write the cleaned file. If not provided, the input file is overwritten.

.PARAMETER NoTrailingDot
  Optional. Don't append a trailing '.' to restored hostnames in record data.

.EXAMPLE
  .\Clean-Zone.ps1 -InputPath ".\zonefile.txt"                 # overwrites zonefile.txt

.EXAMPLE
  .\Clean-Zone.ps1 -InputPath ".\zonefile.txt" -OutputPath ".\cleaned-zone.txt"
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$InputPath,

    [string]$OutputPath,

    [switch]$NoTrailingDot
)

# Fail early if input missing
if (-not (Test-Path -LiteralPath $InputPath)) {
    Write-Error "Input file not found: $InputPath"
    exit 1
}

# Wrapped URL candidate. \s excludes tabs and line breaks as well as spaces,
# so a match can never run past the end of the URL into the rest of the record.
$LinkProtectRegex = '(?i)https?://linkprotect\.cudasvc\.com/url\?[^\s"''<>()\[\]{}]+'
$MaxUnwrapDepth   = 10

# Unwrap one LinkProtect URL (and any LinkProtect URLs nested inside it)
function Get-OriginalFrom-LinkProtect {
    param([string]$wrappedUrl)
    if ([string]::IsNullOrWhiteSpace($wrappedUrl)) { return $null }

    $current = $wrappedUrl
    for ($depth = 0; $depth -lt $MaxUnwrapDepth; $depth++) {
        $current = [System.Net.WebUtility]::HtmlDecode($current)   # &amp; -> &
        if ($current -notmatch '^(?i)https?://linkprotect\.cudasvc\.com/url\?') { break }

        # Pull the 'a' parameter. Its value is percent-encoded, so any '&' inside
        # the original URL is %26 and won't end the match early.
        if ($current -notmatch '(?i)[?&]a=([^&]*)') { return $null }
        $current = [System.Uri]::UnescapeDataString($Matches[1])
        # Loop again: if the decoded value is itself a LinkProtect URL, unwrap it too.
        # (No blanket second decode here - that would corrupt the inner URL's query.)
    }
    return $current
}

# Index of the first ';' that starts a comment (outside quotes), or -1
function Get-CommentIndex {
    param([string]$line)
    $inQuote = $false
    for ($i = 0; $i -lt $line.Length; $i++) {
        $ch = $line[$i]
        if ($ch -eq '\' -and $inQuote) { $i++; continue }
        if ($ch -eq '"') { $inQuote = -not $inQuote; continue }
        if ($ch -eq ';' -and -not $inQuote) { return $i }
    }
    return -1
}

# True if position $pos in $line is inside a "quoted string"
function Test-InQuotes {
    param([string]$line, [int]$pos)
    $inQuote = $false
    for ($i = 0; $i -lt $pos -and $i -lt $line.Length; $i++) {
        $ch = $line[$i]
        if ($ch -eq '\' -and $inQuote) { $i++; continue }
        if ($ch -eq '"') { $inQuote = -not $inQuote }
    }
    return $inQuote
}

# Replace all LinkProtect URLs in one line, using line context to decide formatting
function Replace-LinkProtectUrlsInLine {
    param([string]$line)
    if ([string]::IsNullOrEmpty($line)) { return $line }

    $found = [regex]::Matches($line, $LinkProtectRegex)
    if ($found.Count -eq 0) { return $line }

    $commentIdx = Get-CommentIndex $line
    $sb   = New-Object System.Text.StringBuilder
    $last = 0

    foreach ($m in $found) {
        [void]$sb.Append($line, $last, $m.Index - $last)

        $original = Get-OriginalFrom-LinkProtect $m.Value
        if ([string]::IsNullOrWhiteSpace($original)) {
            $replacement = $m.Value
        }
        elseif ($original -match '^(?i)https?://([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+)$') {
            # Scheme + host with no path/slash = a bare hostname LinkProtect auto-linked.
            $replacement = $Matches[1]
            $inComment = ($commentIdx -ge 0 -and $m.Index -gt $commentIdx)
            $inQuotes  = Test-InQuotes $line $m.Index
            if (-not $NoTrailingDot -and -not $inComment -and -not $inQuotes) {
                $replacement += '.'   # owner/target names must be FQDNs in a zone file
            }
        }
        else {
            $replacement = $original  # a real URL; leave it as-is
        }

        [void]$sb.Append($replacement)
        $last = $m.Index + $m.Length
    }
    [void]$sb.Append($line, $last, $line.Length - $last)
    return $sb.ToString()
}

# Strip http(s):// from record data only - not comments, not quoted TXT content
function Strip-HttpSchemesInLine {
    param([string]$line)
    if ([string]::IsNullOrEmpty($line)) { return $line }
    if ($line.TrimStart().StartsWith(';')) { return $line }

    $commentIdx = Get-CommentIndex $line
    $dataPart   = if ($commentIdx -ge 0) { $line.Substring(0, $commentIdx) } else { $line }
    $restPart   = if ($commentIdx -ge 0) { $line.Substring($commentIdx) } else { '' }

    # Split on quoted strings; even indexes are outside quotes
    $parts = [regex]::Split($dataPart, '("(?:\\.|[^"\\])*")')
    for ($i = 0; $i -lt $parts.Count; $i += 2) {
        $parts[$i] = [regex]::Replace($parts[$i], '(?i)\bhttps?://', '')
    }
    return (-join $parts) + $restPart
}

# Return the RR type token of a record line, or $null
# Zone RR format: [owner] [TTL] [CLASS] TYPE RDATA   (TTL/CLASS optional, either order)
function Get-RecordType {
    param([string]$recordPart)
    if ($recordPart -match '^\s*\$') { return $null }           # $ORIGIN / $TTL directives
    $tokens = @(($recordPart -split '\s+') | Where-Object { $_ -ne '' })
    if ($tokens.Count -eq 0) { return $null }

    # A line starting with whitespace has no owner field (inherits previous owner)
    $i = if ($recordPart -match '^\s') { 0 } else { 1 }
    for ($skip = 0; $skip -lt 2 -and $i -lt $tokens.Count; $skip++) {
        if ($tokens[$i] -match '^\d+[0-9smhdwSMHDW]*$' -or
            $tokens[$i] -match '^(?i)(IN|CH|HS|CS)$') { $i++ } else { break }
    }
    if ($i -lt $tokens.Count) { return $tokens[$i].ToUpperInvariant() }
    return $null
}

# Comment out SOA and NS resource records (most DNS hosts reject them on import).
# A note line is added above each run of commented records.
$ImportNote = ';; Commented out for import usage (SOA/NS are managed by the DNS host)'

function Comment-SOA-NS-Records {
    param([string[]]$lines)

    $result       = New-Object System.Collections.Generic.List[string]
    $inSOABlock   = $false
    $parenDepth   = 0
    $prevComment  = $false   # was the previous line one we commented out?

    foreach ($line in $lines) {
        $commentIdx = Get-CommentIndex $line
        $recordPart = if ($commentIdx -ge 0) { $line.Substring(0, $commentIdx) } else { $line }
        $commentIt  = $false

        if ($inSOABlock) {
            # Continuation lines of a multi-line SOA ( ... )
            $parenDepth += ([regex]::Matches($recordPart, '\(')).Count - ([regex]::Matches($recordPart, '\)')).Count
            if ($parenDepth -le 0) { $inSOABlock = $false; $parenDepth = 0 }
            $commentIt = $true
        }
        else {
            $type = Get-RecordType $recordPart
            if ($type -eq 'NS') { $commentIt = $true }
            elseif ($type -eq 'SOA') {
                $parenDepth = ([regex]::Matches($recordPart, '\(')).Count - ([regex]::Matches($recordPart, '\)')).Count
                $inSOABlock = ($parenDepth -gt 0)
                if (-not $inSOABlock) { $parenDepth = 0 }
                $commentIt = $true
            }
        }

        if ($commentIt) {
            if (-not $prevComment) { $result.Add($ImportNote) }
            $result.Add('; ' + $line)
        } else {
            $result.Add($line)
        }
        $prevComment = $commentIt
    }
    return ,$result.ToArray()
}

# Read whole file (detects BOM/encoding)
try {
    $fullInput = (Resolve-Path -LiteralPath $InputPath).ProviderPath
    $content   = [System.IO.File]::ReadAllText($fullInput)
} catch {
    Write-Error "Failed to read input file: $($_.Exception.Message)"
    exit 1
}

# Preserve the file's own line endings and whether it ended with a newline
$newline        = if ($content -match "`r`n") { "`r`n" } else { "`n" }
$endsWithNewline = $content -match "(`r?`n)$"
if ($endsWithNewline) { $content = $content -replace "(`r?`n)$", '' }
$lines = [regex]::Split($content, "`r?`n")   # (-split "x", -1 behaves differently in PS 5.1 vs 7)

# 1) Decode Barracuda LinkProtect URLs (line by line - never crosses line boundaries)
$lines = @($lines | ForEach-Object { Replace-LinkProtectUrlsInLine $_ })

# 2) Comment out SOA and NS records
$lines = Comment-SOA-NS-Records -lines $lines

# 3) Strip http:// and https:// prefixes from record data
$lines = @($lines | ForEach-Object { Strip-HttpSchemesInLine $_ })

$output = ($lines -join $newline)
if ($endsWithNewline) { $output += $newline }

# Decide output target
$targetPath = if ([string]::IsNullOrWhiteSpace($OutputPath)) { $fullInput } else { $OutputPath }

# Write out (UTF-8, no BOM, no extra newline added)
try {
    if (-not [System.IO.Path]::IsPathRooted($targetPath)) {
        $targetPath = Join-Path (Get-Location).ProviderPath $targetPath
    }
    [System.IO.File]::WriteAllText($targetPath, $output, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host ("Wrote cleaned zone to: {0}" -f $targetPath)
} catch {
    Write-Error "Failed to write output: $($_.Exception.Message)"
    exit 1
}
