<#
linkprotect-file-cleaner.ps1
pellis@cmitsolutions.com
2026.01.13.002

.SYNOPSIS
  Clean a DNS zone file for import:
    - Replace Barracuda LinkProtect URLs with original targets
    - Remove SOA and NS records (handles multi-line SOA)
    - Strip 'http://' and 'https://' scheme prefixes from any URLs

.PARAMETER InputPath
  Path to the input zone file. Required.
  
.PARAMETER OutputPath
  Optional. Path to write the cleaned file. If not provided, the input file is overwritten.

.EXAMPLE
  .\Clean-Zone.ps1 -InputPath ".\zonefile.txt"                 # overwrites zonefile.txt

.EXAMPLE
  .\Clean-Zone.ps1 -InputPath ".\zonefile.txt" -OutputPath ".\cleaned-zone.txt"
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$InputPath,

    [string]$OutputPath
)

# Fail early if input missing
if (-not (Test-Path -LiteralPath $InputPath)) {
    Write-Error "Input file not found: $InputPath"
    exit 1
}

# Helper: HTML decode (&amp; -> &)
function Decode-Html {
    param([string]$s)
    if ($null -eq $s) { return $null }
    return [System.Net.WebUtility]::HtmlDecode($s)
}

# Helper: URL percent-decode
function Decode-Url {
    param([string]$s)
    if ($null -eq $s) { return $null }
    return [System.Uri]::UnescapeDataString($s)
}

# Extract original URL from a Barracuda LinkProtect URL
function Get-OriginalFrom-LinkProtect {
    param([string]$wrappedUrl)
    if ([string]::IsNullOrWhiteSpace($wrappedUrl)) { return $null }

    $normalized = Decode-Html $wrappedUrl

    if ($normalized -notmatch '(?i)https?://linkprotect\.cudasvc\.com/url') { return $null }

    # Parse query for 'a=' parameter
    $query = $null
    try {
        $uri = [System.Uri]$normalized
        $query = $uri.Query.TrimStart('?')
    } catch {
        if ($normalized -match '\?(.*)$') { $query = $Matches[1] }
    }
    if ([string]::IsNullOrEmpty($query)) { return $null }

    $query = Decode-Html $query
    $pairs = $query -split '&'
    $aValue = $null
    foreach ($p in $pairs) {
        if ($p -match '^(?i)a=') {
            $aValue = $p.Substring(2)
            break
        }
    }
    if ([string]::IsNullOrEmpty($aValue)) { return $null }

    $decoded = Decode-Url $aValue
    if ($decoded -match '%[0-9A-Fa-f]{2}') { $decoded = Decode-Url $decoded } # handle double encoding

    return $decoded
}

# Replace all LinkProtect URLs in text with decoded originals
function Replace-LinkProtectUrlsInText {
    param([string]$text)
    if ([string]::IsNullOrEmpty($text)) { return $text }

    # Find candidate wrapped URLs
    $regex = '(?i)https?://linkprotect\.cudasvc\.com/url[^ \)\]\}>"' + "'" + ']+' 

    $evaluator = {
        param([System.Text.RegularExpressions.Match]$m)
        $wrapped = $m.Value
        $original = Get-OriginalFrom-LinkProtect -wrappedUrl $wrapped
        if ([string]::IsNullOrWhiteSpace($original)) { $wrapped } else { $original }
    }

    return [System.Text.RegularExpressions.Regex]::Replace(
        $text,
        $regex,
        [System.Text.RegularExpressions.MatchEvaluator]$evaluator
    )
}

# Strip http:// and https:// scheme prefixes anywhere in the text
function Strip-HttpSchemes {
    param([string]$text)
    if ([string]::IsNullOrEmpty($text)) { return $text }
    # Remove only the scheme, keep the rest of the URL
    return [System.Text.RegularExpressions.Regex]::Replace($text, '(?i)\bhttps?://', '')
}

# Remove SOA and NS resource records from zone content
function Remove-SOA-NS-Records {
    param([string]$text)

    if ([string]::IsNullOrEmpty($text)) { return $text }

    $lines = $text -split "`r?`n", -1
    $result = New-Object System.Collections.Generic.List[string]

    $inSOABlock = $false
    $parenDepth = 0

    foreach ($line in $lines) {
        # Always keep pure comment lines
        if ($line.TrimStart().StartsWith(';')) {
            if (-not $inSOABlock) { $result.Add($line) }
            continue
        }

        # If currently skipping SOA block, update paren depth and continue skipping
        if ($inSOABlock) {
            # Consider only record part before inline comment
            $recordPart = ($line -split ';', 2)[0]
            $openCount  = ([regex]::Matches($recordPart, '\(')).Count
            $closeCount = ([regex]::Matches($recordPart, '\)')).Count
            $parenDepth += ($openCount - $closeCount)
            if ($parenDepth -le 0) {
                # SOA block ended
                $inSOABlock = $false
                $parenDepth = 0
            }
            # Skip this line
            continue
        }

        # Inspect record part (ignore inline comments after ';')
        $recordPart = ($line -split ';', 2)[0]
        $tokens = ($recordPart -split '\s+') | Where-Object { $_ -ne '' }

        if ($tokens.Count -eq 0) {
            # Blank or whitespace line
            $result.Add($line)
            continue
        }

        # Find if this line declares SOA or NS as a type token
        # Zone RR format: <owner> [TTL] [CLASS] TYPE RDATA...
        $typeIndex = $null
        for ($i = 0; $i -lt $tokens.Count; $i++) {
            $tok = $tokens[$i]
            # TYPE is one of known RR types. We specifically seek SOA or NS.
            if ($tok -match '^(?i)SOA$') { $typeIndex = $i; break }
            if ($tok -match '^(?i)NS$')  { $typeIndex = $i; break }
        }

        if ($typeIndex -ne $null) {
            $typeTok = $tokens[$typeIndex].ToUpperInvariant()

            if ($typeTok -eq 'NS') {
                # Skip NS record line
                continue
            }
            elseif ($typeTok -eq 'SOA') {
                # Begin skipping SOA block, including possible multi-line parentheses
                $openCount  = ([regex]::Matches($recordPart, '\(')).Count
                $closeCount = ([regex]::Matches($recordPart, '\)')).Count
                $parenDepth = $openCount - $closeCount
                if ($parenDepth -gt 0) {
                    $inSOABlock = $true
                } else {
                    # One-line SOA without parentheses, just skip this line
                    $inSOABlock = $false
                    $parenDepth = 0
                }
                continue
            }
        }

        # If no SOA or NS detected, keep the line
        $result.Add($line)
    }

    # Join back with original newline semantics (use the predominant newline found)
    return ($result -join "`n")
}

# Read whole file
try {
    $content = Get-Content -LiteralPath $InputPath -Raw
} catch {
    Write-Error "Failed to read input file: $($_.Exception.Message)"
    exit 1
}

# 1) Decode Barracuda LinkProtect URLs
$content = Replace-LinkProtectUrlsInText -text $content

# 2) Remove SOA and NS records
$content = Remove-SOA-NS-Records -text $content

# 3) Strip http:// and https:// prefixes
$content = Strip-HttpSchemes -text $content

# Decide output target
$targetPath = if ([string]::IsNullOrWhiteSpace($OutputPath)) { $InputPath } else { $OutputPath }

# Write out
try {
    Set-Content -LiteralPath $targetPath -Value $content
    Write-Host ("Wrote cleaned zone to: {0}" -f $targetPath)
} catch {
    Write-Error "Failed to write output: $($_.Exception.Message)"
    exit 1
}
