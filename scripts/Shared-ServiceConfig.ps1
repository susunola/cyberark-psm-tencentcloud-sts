function New-SharedServiceConfig {
    param([string]$XmlPath, [string]$ConfigPath)
    $Settings = New-Object System.Xml.XmlReaderSettings
    $Settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $Settings.XmlResolver = $null
    $Reader = $null
    try {
        $Reader = [System.Xml.XmlReader]::Create($XmlPath, $Settings)
        $Document = New-Object System.Xml.XmlDocument
        $Document.XmlResolver = $null
        $Document.Load($Reader)
        if ($Document.DocumentElement.Name -ne 'service') { throw 'Invalid service root.' }
        if ($Document.SelectSingleNode('/service/env[@name="PSM_TC_SHARED_CONFIG"]')) { throw 'Shared entry already exists.' }
        $Entry = $Document.CreateElement('env')
        $Entry.SetAttribute('name', 'PSM_TC_SHARED_CONFIG')
        $Entry.SetAttribute('value', $ConfigPath)
        $null = $Document.DocumentElement.AppendChild($Entry)
        return ,$Document
    } catch {
        throw 'Service XML preflight failed. No changes made; inspect protected configuration.'
    } finally {
        if ($Reader) { $Reader.Dispose() }
    }
}

function Save-SharedServiceConfig {
    param([System.Xml.XmlDocument]$Document, [string]$XmlPath, [string]$BackupPath)
    $TemporaryPath = $XmlPath + '.shared.tmp'
    if ((Test-Path -LiteralPath $BackupPath) -or (Test-Path -LiteralPath $TemporaryPath)) { throw 'Existing backup or temporary file found; inspect before retry.' }
    $Stream = $null
    $Created = $false
    $LockPath = $XmlPath + '.shared.lock'
    $Lock = $null
    try {
        $Lock = [System.IO.File]::Open($LockPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        # Check again while holding the lock, including delayed concurrent invocations.
        if (Test-Path -LiteralPath $BackupPath) { throw 'Backup appeared during update.' }
        $Stream = [System.IO.File]::Open($TemporaryPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $Created = $true
        $Document.Save($Stream)
        $Stream.Flush($true)
        $Stream.Dispose()
        $Stream = $null
        # Same-volume atomic replacement preserves a recoverable original.
        [System.IO.File]::Replace($TemporaryPath, $XmlPath, $BackupPath)
    } catch {
        throw 'Service XML replacement failed. Inspect original and backup before retry.'
    } finally {
        if ($Stream) { $Stream.Dispose() }
        if ($Created -and (Test-Path -LiteralPath $TemporaryPath)) { Remove-Item -LiteralPath $TemporaryPath -Force }
        if ($Lock) { $Lock.Dispose(); Remove-Item -LiteralPath $LockPath -Force }
    }
}
