[CmdletBinding()]
param(
    [string]$RegFile = '',
    [ValidateSet('LocalMachine', 'CurrentUser')]
    [string]$Hive = 'LocalMachine',
    [string]$RegistryPath = 'SOFTWARE\Affix'
)

$ErrorActionPreference = 'Stop'
if (-not $RegFile) {
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $RegFile = Join-Path $scriptDir 'affix.reg'
}
# Parse completely before changing registry state. This script is for the shipped
# Mode/Affinity REG_SZ subset only, never an arbitrary registry script.
$lines = [IO.File]::ReadAllLines($RegFile)
if ($lines.Count -eq 0 -or $lines[0].Trim([char]0xfeff).Trim() -ne 'Windows Registry Editor Version 5.00') {
    throw 'Invalid Affix registry file header.'
}
$rules = [Collections.Generic.List[object]]::new()
$names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$current = $null
foreach ($rawLine in $lines | Select-Object -Skip 1) {
    $line = $rawLine.Trim()
    if (-not $line -or $line.StartsWith(';')) { continue }
    if ($line -match '^\[HKEY_LOCAL_MACHINE\\SOFTWARE\\Affix\\([^\\/\x00]{1,255})\]$') {
        $image = $Matches[1].ToLowerInvariant()
        if (-not $names.Add($image)) { throw "Duplicate image: $image" }
        $current = [pscustomobject]@{ Image = $image; Values = @{} }
        $rules.Add($current)
    } elseif ($null -ne $current -and $line -match '^"(Mode|Affinity)"="([^"\\\x00]+)"$') {
        $field = $Matches[1]
        $value = $Matches[2]
        if ($current.Values.ContainsKey($field)) { throw "Duplicate $field for $($current.Image)" }
        if ($field -eq 'Mode' -and $value -cnotin @('normal', 'efficiency', 'performance', 'realtime')) {
            throw "Invalid mode: $value"
        }
        if ($field -eq 'Affinity' -and $value -cnotmatch '^(P|E|LPE|C|[0-9]+)(\+(P|E|LPE|C|[0-9]+))*$') {
            throw "Invalid affinity: $value"
        }
        $current.Values[$field] = $value
    } else {
        throw "Unsupported Affix registry file line: $line"
    }
}

$base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
    [Microsoft.Win32.RegistryHive]::$Hive, [Microsoft.Win32.RegistryView]::Registry64)
$root = $null
$created = [Collections.Generic.List[string]]::new()
try {
    $root = $base.CreateSubKey($RegistryPath, $true)
    foreach ($rule in $rules) {
        $existing = $root.OpenSubKey($rule.Image)
        if ($null -ne $existing) {
            $existing.Dispose()
            continue
        }
        $key = $root.CreateSubKey($rule.Image, $true)
        $created.Add($rule.Image)
        try {
            foreach ($field in $rule.Values.Keys) {
                $key.SetValue($field, $rule.Values[$field], [Microsoft.Win32.RegistryValueKind]::String)
            }
        } finally {
            $key.Dispose()
        }
    }
} catch {
    # Roll back only keys created by this invocation; existing policies are retained.
    foreach ($image in $created) { $root.DeleteSubKeyTree($image, $false) }
    throw
} finally {
    if ($null -ne $root) { $root.Dispose() }
    $base.Dispose()
}
Write-Output "Imported $($created.Count) missing Affix application policies."
