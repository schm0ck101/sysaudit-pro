"""Scripts PowerShell de collecte (Windows PowerShell 5.1, présent sur
Windows 10/11 et Windows Server 2016+).

Chaque script renvoie UN objet JSON sur la sortie standard. Les sections sont
indépendantes : une section en erreur (droits, rôle absent…) est notée dans
`_errors` sans empêcher les autres. Les dates sont converties en ISO 8601 côté
PowerShell (ConvertTo-Json 5.1 produit sinon des "\\/Date(…)\\/").
Les noms de classes WMI / CIM et de fournisseurs d'événements ne dépendent pas
de la langue de Windows ; aucun texte localisé n'est analysé.
"""

PRELUDE = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}
$R = [ordered]@{}
$script:E = New-Object System.Collections.ArrayList
function D($d) { if ($null -eq $d -or "$d" -eq '') { return $null }; try { return ([datetime]$d).ToString('o') } catch { return $null } }
function T([string]$k, [scriptblock]$b) {
  try { $R[$k] = & $b } catch { [void]$script:E.Add("${k}: $($_.Exception.Message)") }
}
# TL : section de type liste (PowerShell « déroule » un tableau d'un seul élément)
function TL([string]$k, [scriptblock]$b) {
  try { $R[$k] = @(& $b | Where-Object { $null -ne $_ }) } catch { [void]$script:E.Add("${k}: $($_.Exception.Message)") }
}
function WE($f, [int]$max) {
  # Get-WinEvent lève une erreur quand rien ne correspond : c'est « zéro événement », pas un échec
  try { return @(Get-WinEvent -FilterHashtable $f -MaxEvents $max -ErrorAction Stop) }
  catch { if ("$($_.FullyQualifiedErrorId)" -like 'NoMatchingEventsFound*') { return @() } else { throw } }
}
function RegV($path, $name) {
  try { $v = Get-ItemProperty -LiteralPath $path -Name $name -ErrorAction Stop; return $v.$name } catch { return $null }
}
$IsAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$R['is_admin'] = $IsAdmin
"""

EPILOGUE = r"""
$R['_errors'] = @($script:E)
$R | ConvertTo-Json -Depth 7 -Compress
"""

# ---------------------------------------------------------------- système
SYSTEM = r"""
T 'os' {
  $o = Get-CimInstance Win32_OperatingSystem
  $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  [ordered]@{ caption = $o.Caption; version = $o.Version; build = [int]$o.BuildNumber; ubr = (RegV $cv 'UBR');
    display_version = (RegV $cv 'DisplayVersion'); edition = (RegV $cv 'EditionID'); installation_type = (RegV $cv 'InstallationType');
    arch = $o.OSArchitecture; product_type = [int]$o.ProductType; install_date = (D $o.InstallDate);
    last_boot = (D $o.LastBootUpTime); now = (D (Get-Date)); language = $o.OSLanguage; locale = (Get-Culture).Name;
    total_kb = [int64]$o.TotalVisibleMemorySize; free_kb = [int64]$o.FreePhysicalMemory;
    virt_total_kb = [int64]$o.TotalVirtualMemorySize; virt_free_kb = [int64]$o.FreeVirtualMemory;
    system_drive = $o.SystemDrive; registered_user = $o.RegisteredUser; organization = $o.Organization }
}
T 'computer' {
  $c = Get-CimInstance Win32_ComputerSystem
  [ordered]@{ name = $c.Name; dns_host = $c.DNSHostName; domain = $c.Domain; part_of_domain = [bool]$c.PartOfDomain;
    domain_role = [int]$c.DomainRole; manufacturer = $c.Manufacturer; model = $c.Model; system_family = $c.SystemFamily;
    total_bytes = [int64]$c.TotalPhysicalMemory; logical_cpus = [int]$c.NumberOfLogicalProcessors;
    pc_type = [int]$c.PCSystemType; hypervisor = [bool]$c.HypervisorPresent; auto_pagefile = [bool]$c.AutomaticManagedPagefile }
}
T 'bios' {
  $b = Get-CimInstance Win32_BIOS
  [ordered]@{ manufacturer = $b.Manufacturer; version = $b.SMBIOSBIOSVersion; release = (D $b.ReleaseDate); serial = $b.SerialNumber }
}
T 'board' { $b = Get-CimInstance Win32_BaseBoard; [ordered]@{ manufacturer = $b.Manufacturer; product = $b.Product } }
TL 'cpu' {
  @(Get-CimInstance Win32_Processor | ForEach-Object { [ordered]@{ name = $_.Name.Trim(); cores = [int]$_.NumberOfCores;
    logical = [int]$_.NumberOfLogicalProcessors; max_mhz = [int]$_.MaxClockSpeed; current_mhz = [int]$_.CurrentClockSpeed;
    virtualization = [bool]$_.VirtualizationFirmwareEnabled } })
}
TL 'cpu_load' {
  $s = @(); for ($i = 0; $i -lt 3; $i++) {
    $p = Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'"
    $s += [int]$p.PercentProcessorTime; Start-Sleep -Milliseconds 900 }
  $s
}
TL 'ram_modules' {
  @(Get-CimInstance Win32_PhysicalMemory | ForEach-Object { [ordered]@{ capacity = [int64]$_.Capacity; speed = [int]$_.Speed;
    configured_speed = [int]$_.ConfiguredClockSpeed; manufacturer = "$($_.Manufacturer)".Trim(); part = "$($_.PartNumber)".Trim(); slot = $_.DeviceLocator } })
}
T 'ram_slots' { $a = Get-CimInstance Win32_PhysicalMemoryArray; [ordered]@{ slots = [int](($a | Measure-Object MemoryDevices -Sum).Sum); max_kb = [int64](($a | Measure-Object MaxCapacityEx -Sum).Sum) } }
T 'memory_perf' {
  $m = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory
  [ordered]@{ committed = [int64]$m.CommittedBytes; commit_limit = [int64]$m.CommitLimit; available_mb = [int64]$m.AvailableMBytes;
    pool_nonpaged = [int64]$m.PoolNonpagedBytes; pool_paged = [int64]$m.PoolPagedBytes; pages_sec = [int64]$m.PagesPersec;
    cache = [int64]$m.CacheBytes; compressed = $null }
}
TL 'pagefile' {
  @(Get-CimInstance Win32_PageFileUsage | ForEach-Object { [ordered]@{ name = $_.Name; allocated_mb = [int]$_.AllocatedBaseSize;
    current_mb = [int]$_.CurrentUsage; peak_mb = [int]$_.PeakUsage } })
}
TL 'disk_perf' {
  @(Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk | Where-Object Name -ne '_Total' | ForEach-Object {
    [ordered]@{ name = $_.Name; queue = [double]$_.AvgDiskQueueLength; busy = [int]$_.PercentDiskTime;
      read_s = [double]$_.AvgDisksecPerRead; write_s = [double]$_.AvgDisksecPerWrite } })
}
T 'processes' {
  $cpu = @{}
  try { Get-CimInstance Win32_PerfFormattedData_PerfProc_Process | ForEach-Object { $cpu[[int]$_.IDProcess] = [int]$_.PercentProcessorTime } } catch {}
  $now = Get-Date
  $all = @(Get-Process)
  $tot = [ordered]@{ count = $all.Count; handles = [int64](($all | Measure-Object HandleCount -Sum).Sum);
    threads = [int64](($all | ForEach-Object { $_.Threads.Count } | Measure-Object -Sum).Sum) }
  $sel = @($all | Sort-Object PrivateMemorySize64 -Descending | Select-Object -First 12) + @($all | Sort-Object HandleCount -Descending | Select-Object -First 8) + @($all | Where-Object { $cpu[$_.Id] -gt 5 })
  $seen = @{}
  $top = foreach ($p in $sel) { if ($seen[$p.Id]) { continue }; $seen[$p.Id] = 1
    $st = $null; try { $st = D $p.StartTime } catch {}
    $path = $null; try { $path = $p.Path } catch {}
    [ordered]@{ name = $p.ProcessName; pid = $p.Id; private = [int64]$p.PrivateMemorySize64; ws = [int64]$p.WorkingSet64;
      handles = [int]$p.HandleCount; threads = [int]$p.Threads.Count; cpu_pct = $cpu[[int]$p.Id]; start = $st; path = $path;
      company = $(try { $p.Company } catch { $null }) } }
  [ordered]@{ totals = $tot; top = @($top) }
}
TL 'pending_reboot' {
  $r = @()
  if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $r += 'cbs' }
  if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $r += 'windows_update' }
  if (RegV 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations') { $r += 'file_rename' }
  try { $u = Invoke-CimMethod -Namespace root\ccm\ClientSDK -ClassName CCM_ClientUtilities -MethodName DetermineIfRebootPending -ErrorAction Stop
        if ($u.RebootPending -or $u.IsHardRebootPending) { $r += 'sccm' } } catch {}
  $r
}
T 'secure_boot' {
  $v = RegV 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled'
  $fw = $null; try { $fw = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name PEFirmwareType -ErrorAction Stop).PEFirmwareType } catch {}
  [ordered]@{ enabled = $v; firmware = $fw }
}
T 'tpm' {
  $t = Get-CimInstance -Namespace root\cimv2\Security\MicrosoftTpm -ClassName Win32_Tpm
  if ($t) { [ordered]@{ present = $true; enabled = [bool]$t.IsEnabled_InitialValue; activated = [bool]$t.IsActivated_InitialValue;
    spec = $t.SpecVersion; manufacturer = $t.ManufacturerIdTxt } } else { [ordered]@{ present = $false } }
}
T 'device_guard' {
  $g = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard
  [ordered]@{ vbs = [int]$g.VirtualizationBasedSecurityStatus; running = @($g.SecurityServicesRunning | ForEach-Object { [int]$_ });
    configured = @($g.SecurityServicesConfigured | ForEach-Object { [int]$_ }) }
}
T 'battery' {
  $b = @(Get-CimInstance Win32_Battery)
  if ($b.Count -eq 0) { $null } else {
    $design = $null; $full = $null; $cycles = $null
    try { $design = [int64]((Get-CimInstance -Namespace root\wmi -ClassName BatteryStaticData | Measure-Object DesignedCapacity -Sum).Sum) } catch {}
    try { $full = [int64]((Get-CimInstance -Namespace root\wmi -ClassName BatteryFullChargedCapacity | Measure-Object FullChargedCapacity -Sum).Sum) } catch {}
    try { $cycles = [int]((Get-CimInstance -Namespace root\wmi -ClassName BatteryCycleCount | Measure-Object CycleCount -Maximum).Maximum) } catch {}
    [ordered]@{ count = $b.Count; name = $b[0].Name; charge = [int]$b[0].EstimatedChargeRemaining; status = [int]$b[0].BatteryStatus;
      design_mwh = $design; full_mwh = $full; cycles = $cycles }
  }
}
TL 'thermal' {
  @(Get-CimInstance -Namespace root\wmi -ClassName MSAcpi_ThermalZoneTemperature | ForEach-Object {
    [ordered]@{ zone = $_.InstanceName; celsius = [math]::Round($_.CurrentTemperature / 10 - 273.15, 1);
      critical = [math]::Round($_.CriticalTripPoint / 10 - 273.15, 1) } })
}
T 'power_plan' {
  $o = & "$env:windir\System32\powercfg.exe" /getactivescheme 2>&1 | Out-String
  $m = [regex]::Match($o, '([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\s*\((.*)\)')
  if ($m.Success) { [ordered]@{ id = $m.Groups[1].Value; name = $m.Groups[2].Value.Trim() } } else { $null }
}
TL 'gpu' {
  @(Get-CimInstance Win32_VideoController | ForEach-Object { [ordered]@{ name = $_.Name; driver = $_.DriverVersion;
    driver_date = (D $_.DriverDate); ram = [int64]$_.AdapterRAM; status = $_.Status } })
}
T 'timezone' { (Get-TimeZone).Id }
"""

# ---------------------------------------------------------------- disques
DISKS = r"""
TL 'physical' {
  @(Get-PhysicalDisk | ForEach-Object {
    $d = $_
    $rc = $null
    try { $c = $d | Get-StorageReliabilityCounter -ErrorAction Stop
      $rc = [ordered]@{ temperature = $c.Temperature; temperature_max = $c.TemperatureMax; wear = $c.Wear;
        read_errors = $c.ReadErrorsTotal; read_uncorrected = $c.ReadErrorsUncorrected; write_errors = $c.WriteErrorsTotal;
        write_uncorrected = $c.WriteErrorsUncorrected; power_on_hours = $c.PowerOnHours; start_stop = $c.StartStopCycleCount;
        load_unload = $c.LoadUnloadCycleCount; read_latency_max = $c.ReadLatencyMax; write_latency_max = $c.WriteLatencyMax;
        flush_latency_max = $c.FlushLatencyMax; manufacture_date = $c.ManufactureDate; updated = (D $c.UpdateDateTime) } } catch {}
    [ordered]@{ id = "$($d.DeviceId)"; name = $d.FriendlyName; serial = "$($d.SerialNumber)".Trim(); media = "$($d.MediaType)"; bus = "$($d.BusType)";
      size = [int64]$d.Size; health = "$($d.HealthStatus)"; operational = @($d.OperationalStatus | ForEach-Object { "$_" });
      firmware = $d.FirmwareVersion; spindle = $d.SpindleSpeed; model = $d.Model; reliability = $rc }
  })
}
TL 'smart_predict' {
  @(Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus | ForEach-Object {
    [ordered]@{ instance = $_.InstanceName; predict_failure = [bool]$_.PredictFailure; reason = [int]$_.Reason } })
}
TL 'volumes' {
  @(Get-CimInstance Win32_Volume -Filter 'DriveType=3' | ForEach-Object {
    [ordered]@{ letter = $_.DriveLetter; label = $_.Label; fs = $_.FileSystem; size = [int64]$_.Capacity; free = [int64]$_.FreeSpace;
      dirty = $_.DirtyBitSet; system = [bool]$_.SystemVolume; boot = [bool]$_.BootVolume; name = $_.Name; pagefile = [bool]$_.PageFilePresent } })
}
TL 'volume_health' {
  @(Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' } | ForEach-Object {
    [ordered]@{ letter = "$($_.DriveLetter)"; health = "$($_.HealthStatus)"; operational = "$($_.OperationalStatus)"; fs = $_.FileSystemType;
      dedup = "$($_.DedupMode)" } })
}
function DirSize([string]$path, [int]$budgetMs) {
  if (-not (Test-Path -LiteralPath $path)) { return $null }
  $sw = [Diagnostics.Stopwatch]::StartNew(); $total = [int64]0; $files = 0; $partial = $false
  $stack = New-Object System.Collections.Stack; $stack.Push((New-Object IO.DirectoryInfo $path))
  while ($stack.Count -gt 0) {
    if ($sw.ElapsedMilliseconds -gt $budgetMs) { $partial = $true; break }
    $d = $stack.Pop()
    try { foreach ($f in $d.GetFiles()) { $total += $f.Length; $files++ } } catch {}
    try { foreach ($s in $d.GetDirectories()) { if (-not ($s.Attributes -band [IO.FileAttributes]::ReparsePoint)) { $stack.Push($s) } } } catch {}
  }
  [ordered]@{ path = $path; bytes = $total; files = $files; partial = $partial }
}
TL 'folders' {
  $w = $env:windir; $sd = $env:SystemDrive
  @( (DirSize "$w\Temp" 4000), (DirSize $env:TEMP 4000), (DirSize "$w\SoftwareDistribution\Download" 4000),
     (DirSize "$sd\Windows.old" 6000), (DirSize "$w\Minidump" 1000), (DirSize "$w\LiveKernelReports" 1000),
     (DirSize "$w\Logs\CBS" 2000), (DirSize "$env:ProgramData\Microsoft\Windows\WER" 3000),
     (DirSize "$sd\`$Recycle.Bin" 3000) ) | Where-Object { $_ }
}
T 'memory_dump' {
  $f = Get-Item -LiteralPath "$env:windir\MEMORY.DMP" -Force -ErrorAction SilentlyContinue
  if ($f) { [ordered]@{ bytes = [int64]$f.Length; date = (D $f.LastWriteTime) } } else { $null }
}
TL 'minidumps' {
  @(Get-ChildItem -LiteralPath "$env:windir\Minidump" -Filter *.dmp -Force -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending |
    Select-Object -First 30 | ForEach-Object { [ordered]@{ name = $_.Name; date = (D $_.LastWriteTime); bytes = [int64]$_.Length } })
}
"""

# ---------------------------------------------------------------- journaux
EVENTS = r"""
$days = [int]'__DAYS__'
$start = (Get-Date).AddDays(-$days)
function Agg($events, [string[]]$keyProps) {
  $g = @{}
  foreach ($e in $events) {
    $extra = ''
    # regroupement plus fin : par application, par mise à jour, par service
    if ($e.ProviderName -eq 'Application Error' -or $e.ProviderName -eq 'Application Hang') {
      try { $extra = "$($e.Properties[0].Value)" } catch {} }
    elseif ($e.ProviderName -eq 'Microsoft-Windows-WindowsUpdateClient') { try { $extra = "$($e.Properties[1].Value)" } catch {} }
    elseif ($e.ProviderName -eq 'Service Control Manager' -and $e.Id -ne 7036) { try { $extra = "$($e.Properties[0].Value)" } catch {} }
    $k = "$($e.LogName)|$($e.ProviderName)|$($e.Id)|$extra"
    if (-not $g.ContainsKey($k)) {
      $msg = $null; try { $msg = $e.FormatDescription() } catch {}
      if (-not $msg) { try { $msg = $e.Message } catch {} }
      if ($msg -and $msg.Length -gt 500) { $msg = $msg.Substring(0, 500) }
      $g[$k] = [ordered]@{ log = $e.LogName; provider = $e.ProviderName; id = [int]$e.Id; level = [int]$e.Level; key = $extra;
        count = 0; first = $null; last = $null; days = @{}; message = $msg; props = @() }
      try { $g[$k].props = @($e.Properties | Select-Object -First 8 | ForEach-Object { "$($_.Value)" }) } catch {}
    }
    $x = $g[$k]; $x.count++
    $t = $e.TimeCreated
    if (-not $x.last -or $t -gt [datetime]$x.last) { $x.last = $t.ToString('o') }
    if (-not $x.first -or $t -lt [datetime]$x.first) { $x.first = $t.ToString('o') }
    $dk = $t.ToString('yyyy-MM-dd'); if ($x.days.ContainsKey($dk)) { $x.days[$dk]++ } else { $x.days[$dk] = 1 }
  }
  @($g.Values)
}
TL 'system_errors' {
  $ev = (WE @{ LogName = 'System'; Level = 1, 2; StartTime = $start } 6000)
  Agg $ev @()
}
TL 'system_warnings' {
  # avertissements significatifs (matériel, ressources, disque, thermique)
  $prov = @('disk', 'Disk', 'Ntfs', 'Microsoft-Windows-Ntfs', 'storahci', 'stornvme', 'iaStorA', 'iaStorAC', 'iaStorAVC', 'Microsoft-Windows-WHEA-Logger',
            'Microsoft-Windows-Resource-Exhaustion-Detector', 'Microsoft-Windows-Kernel-Processor-Power', 'Microsoft-Windows-Kernel-Power',
            'volmgr', 'Microsoft-Windows-Time-Service', 'Microsoft-Windows-DNS-Client', 'NETLOGON', 'Microsoft-Windows-GroupPolicy',
            'Microsoft-Windows-Kernel-Boot', 'Microsoft-Windows-StorPort', 'Microsoft-Windows-Kernel-PnP', 'nvlddmkm', 'amdkmdag', 'Display')
  # (un ProviderName absent du poste ferait échouer tout le filtre : tri côté script)
  $ev = @((WE @{ LogName = 'System'; Level = 3; StartTime = $start } 10000) | Where-Object { $prov -contains $_.ProviderName })
  Agg $ev @()
}
TL 'application_errors' {
  $ev = (WE @{ LogName = 'Application'; Level = 1, 2; StartTime = $start } 6000)
  Agg $ev @('app')
}
TL 'boot_perf' {
  @(WE @{ LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = 100; StartTime = (Get-Date).AddDays(-120) } 200 |
    ForEach-Object { $x = [xml]$_.ToXml(); $bt = ($x.Event.EventData.Data | Where-Object Name -eq 'BootTime').'#text'
      $mp = ($x.Event.EventData.Data | Where-Object Name -eq 'MainPathBootTime').'#text'
      [ordered]@{ date = (D $_.TimeCreated); boot_ms = [int]$bt; main_ms = [int]$mp } })
}
TL 'boot_degradation' {
  @(WE @{ LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = 101, 102, 103, 106, 109; StartTime = (Get-Date).AddDays(-60) } 300 |
    ForEach-Object { $x = [xml]$_.ToXml(); $d = @{}; foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
      [ordered]@{ id = [int]$_.Id; date = (D $_.TimeCreated); name = $d['FriendlyName']; file = $d['FileName']; total_ms = [int]$d['TotalTime']; degradation_ms = [int]$d['DegradationTime'] } })
}
T 'security_logons' {
  $ev = (WE @{ LogName = 'Security'; Id = 4625; StartTime = (Get-Date).AddDays(-7) } 20000)
  $by = @{}
  foreach ($e in $ev) { $x = [xml]$e.ToXml(); $d = @{}; foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
    $k = "$($d['TargetUserName'])|$($d['IpAddress'])|$($d['LogonType'])"; if ($by.ContainsKey($k)) { $by[$k]++ } else { $by[$k] = 1 } }
  $lock = (WE @{ LogName = 'Security'; Id = 4740; StartTime = (Get-Date).AddDays(-7) } 500).Count
  [ordered]@{ failed = $ev.Count; lockouts = $lock; top = @($by.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 8 |
    ForEach-Object { $p = $_.Key.Split('|'); [ordered]@{ user = $p[0]; ip = $p[1]; type = $p[2]; count = $_.Value } }) }
}
TL 'log_coverage' {
  @('System', 'Application') | ForEach-Object {
    $o = Get-WinEvent -LogName $_ -MaxEvents 1 -Oldest -ErrorAction SilentlyContinue
    $l = Get-WinEvent -ListLog $_ -ErrorAction SilentlyContinue
    [ordered]@{ log = $_; oldest = (D $o.TimeCreated); max_bytes = [int64]$l.MaximumSizeInBytes; records = [int64]$l.RecordCount; mode = "$($l.LogMode)" } }
}
TL 'reliability' {
  @(Get-CimInstance Win32_ReliabilityStabilityMetrics -ErrorAction Stop | Select-Object -First 2000 | ForEach-Object {
    [ordered]@{ t = (D $_.TimeGenerated); v = [double]$_.SystemStabilityIndex } })
}
TL 'wer_reports' {
  $c = @{}; $since = (Get-Date).AddDays(-$days)
  foreach ($dir in @("$env:ProgramData\Microsoft\Windows\WER\ReportArchive", "$env:ProgramData\Microsoft\Windows\WER\ReportQueue")) {
    Get-ChildItem -LiteralPath $dir -Directory -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt $since } | ForEach-Object {
      $n = $_.Name -replace '_[0-9a-f]{20,}.*$', '' -replace '^(AppCrash|AppHang|Kernel|BlueScreen|LiveKernelEvent|APPCRASH|Critical)_', '$1|'
      if ($c.ContainsKey($n)) { $c[$n]++ } else { $c[$n] = 1 } } }
  @($c.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 25 | ForEach-Object { [ordered]@{ name = $_.Key; count = $_.Value } })
}
"""

# ---------------------------------------------------------------- mises à jour
UPDATES = r"""
TL 'hotfixes' {
  @(Get-CimInstance Win32_QuickFixEngineering | ForEach-Object {
    $d = $null; try { $d = D $_.InstalledOn } catch {}
    if (-not $d) { try { $d = D ([datetime]::Parse("$($_.InstalledOn)", [Globalization.CultureInfo]::InvariantCulture)) } catch {} }
    [ordered]@{ id = $_.HotFixID; description = $_.Description; installed = $d } })
}
TL 'history' {
  $s = New-Object -ComObject Microsoft.Update.Session
  $searcher = $s.CreateUpdateSearcher()
  $n = $searcher.GetTotalHistoryCount()
  if ($n -gt 0) { @($searcher.QueryHistory(0, [math]::Min($n, 120)) | Where-Object { $_.Operation -eq 1 } | ForEach-Object {
    [ordered]@{ title = $_.Title; date = (D $_.Date); result = [int]$_.ResultCode; hresult = [int64]$_.HResult } }) } else { @() }
}
T 'wu_policy' {
  $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
  [ordered]@{ wsus = (RegV $p 'WUServer'); use_wsus = (RegV "$p\AU" 'UseWUServer'); no_auto = (RegV "$p\AU" 'NoAutoUpdate');
    au_option = (RegV "$p\AU" 'AUOptions'); deferral_quality = (RegV $p 'DeferQualityUpdatesPeriodInDays');
    paused_until = (RegV 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' 'PauseUpdatesExpiryTime') }
}
TL 'wu_services' {
  @('wuauserv', 'BITS', 'UsoSvc', 'TrustedInstaller', 'CryptSvc') | ForEach-Object {
    $s = Get-CimInstance Win32_Service -Filter "Name='$_'"; if ($s) { [ordered]@{ name = $s.Name; start = $s.StartMode; state = $s.State } } }
}
T 'pending_checked' { $false }
TL 'pending' {
  if ('__ONLINE__' -ne '1') { return }
  $s = New-Object -ComObject Microsoft.Update.Session
  $searcher = $s.CreateUpdateSearcher()
  $searcher.Online = $true
  $r = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
  $R['pending_checked'] = $true
  @($r.Updates | ForEach-Object { [ordered]@{ title = $_.Title; severity = $_.MsrcSeverity; kb = @($_.KBArticleIDs);
    published = (D $_.LastDeploymentChangeTime); reboot = [bool]$_.RebootRequired; categories = @($_.Categories | ForEach-Object { $_.Name }) } })
}
"""

# ---------------------------------------------------------------- services, logiciels
SOFTWARE = r"""
TL 'services' {
  @(Get-CimInstance Win32_Service | ForEach-Object {
    $trig = $false; $delayed = $null
    if ($_.StartMode -eq 'Auto' -and $_.State -ne 'Running') {
      $trig = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Name)\TriggerInfo"
      $delayed = RegV "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Name)" 'DelayedAutostart' }
    [ordered]@{ name = $_.Name; display = $_.DisplayName; start = $_.StartMode; state = $_.State; exit = [int]$_.ExitCode;
      specific_exit = [int]$_.ServiceSpecificExitCode; path = $_.PathName; account = $_.StartName; trigger = $trig; delayed = $delayed } })
}
TL 'tasks' {
  @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
    $t = $_; $i = $null; try { $i = $t | Get-ScheduledTaskInfo -ErrorAction Stop } catch {}
    $exe = $null; try { $exe = "$($t.Actions[0].Execute)" } catch {}
    [ordered]@{ name = $t.TaskName; path = $t.TaskPath; state = "$($t.State)"; author = $t.Author; exe = $exe; args = $(try { "$($t.Actions[0].Arguments)" } catch { $null });
      user = "$($t.Principal.UserId)"; last_run = $(if ($i) { D $i.LastRunTime }); last_result = $(if ($i) { [int64]$i.LastTaskResult });
      next_run = $(if ($i) { D $i.NextRunTime }); missed = $(if ($i) { [int]$i.NumberOfMissedRuns }) } })
}
TL 'startup' {
  @(Get-CimInstance Win32_StartupCommand | ForEach-Object { [ordered]@{ name = $_.Name; command = $_.Command; location = $_.Location; user = $_.User } })
}
TL 'software' {
  $keys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')
  @(Get-ItemProperty $keys -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and -not $_.SystemComponent -and -not $_.ParentKeyName } | ForEach-Object {
    [pscustomobject]@{ name = "$($_.DisplayName)".Trim(); version = "$($_.DisplayVersion)"; publisher = "$($_.Publisher)"; installed = "$($_.InstallDate)";
      size_kb = $_.EstimatedSize; scope = $(if ($_.PSPath -like '*HKEY_CURRENT_USER*') { 'user' } else { 'machine' }) } } | Sort-Object name, version -Unique)
}
T 'appx_count' { @(Get-AppxPackage -ErrorAction Stop).Count }
TL 'devices' {
  @(Get-CimInstance Win32_PnPEntity -Filter 'ConfigManagerErrorCode <> 0' | ForEach-Object {
    [ordered]@{ name = $_.Name; code = [int]$_.ConfigManagerErrorCode; class = $_.PNPClass; id = $_.PNPDeviceID; present = [bool]$_.Present } })
}
TL 'drivers' {
  @(Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DeviceName -and $_.DriverProviderName -and $_.DriverProviderName -notmatch '^Microsoft' } |
    ForEach-Object { [ordered]@{ device = $_.DeviceName; provider = $_.DriverProviderName; version = $_.DriverVersion;
      date = (D $_.DriverDate); signed = $_.IsSigned; class = $_.DeviceClass } })
}
T 'features' {
  $r = [ordered]@{}
  try { $r.server_features = @(Get-WindowsFeature -ErrorAction Stop | Where-Object Installed | ForEach-Object Name) } catch {}
  $r
}
T 'sfc_state' {
  # dernier résultat de vérification du magasin de composants (CBS) sans relancer d'analyse
  $f = "$env:windir\Logs\CBS\CBS.log"
  if (Test-Path $f) { [ordered]@{ size = (Get-Item $f).Length; date = (D (Get-Item $f).LastWriteTime) } } else { $null }
}
T 'dism_health' {
  if (-not $IsAdmin) { return $null }
  $o = & "$env:windir\System32\Dism.exe" /English /Online /Cleanup-Image /CheckHealth 2>&1 | Out-String
  [ordered]@{ output = $o.Trim(); exit = $LASTEXITCODE }
}
"""

# ---------------------------------------------------------------- réseau
NETWORK = r"""
TL 'adapters' {
  @(Get-NetAdapter -ErrorAction Stop | ForEach-Object {
    $st = $null; try { $s = $_ | Get-NetAdapterStatistics -ErrorAction Stop
      $st = [ordered]@{ rx = [int64]$s.ReceivedBytes; tx = [int64]$s.SentBytes; rx_errors = [int64]$s.ReceivedPacketErrors; tx_errors = [int64]$s.OutboundPacketErrors;
        rx_discarded = [int64]$s.ReceivedDiscardedPackets; tx_discarded = [int64]$s.OutboundDiscardedPackets; rx_packets = [int64]$s.ReceivedUnicastPackets } } catch {}
    [ordered]@{ name = $_.Name; description = $_.InterfaceDescription; status = "$($_.Status)"; speed = "$($_.LinkSpeed)";
      bps = [int64]$_.ReceiveLinkSpeed; media = "$($_.PhysicalMediaType)"; mac = $_.MacAddress; virtual = [bool]$_.Virtual; hidden = [bool]$_.Hidden;
      driver_date = "$($_.DriverDate)"; driver_version = $_.DriverVersionString; index = [int]$_.ifIndex; stats = $st } })
}
TL 'ip' {
  @(Get-NetIPConfiguration -ErrorAction Stop | ForEach-Object {
    [ordered]@{ alias = $_.InterfaceAlias; index = [int]$_.InterfaceIndex; ipv4 = @($_.IPv4Address | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" });
      ipv6 = @($_.IPv6Address | ForEach-Object { "$($_.IPAddress)" }); gateway = @($_.IPv4DefaultGateway | ForEach-Object { $_.NextHop });
      dns = @($_.DNSServer | Where-Object AddressFamily -eq 2 | ForEach-Object { $_.ServerAddresses }); profile = "$($_.NetProfile.NetworkCategory)";
      dhcp = "$($_.NetIPv4Interface.Dhcp)" } })
}
T 'connectivity' {
  $r = [ordered]@{}
  $gw = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1)
  function P($h) { $p = New-Object System.Net.NetworkInformation.Ping; $ok = 0; $t = @()
    for ($i = 0; $i -lt 4; $i++) { try { $x = $p.Send($h, 1000); if ($x.Status -eq 'Success') { $ok++; $t += $x.RoundtripTime } } catch {} }
    [ordered]@{ host = $h; sent = 4; received = $ok; avg_ms = $(if ($t.Count) { [math]::Round(($t | Measure-Object -Average).Average, 1) } else { $null });
      max_ms = $(if ($t.Count) { ($t | Measure-Object -Maximum).Maximum } else { $null }) } }
  if ($gw.Count) { $r.gateway = P $gw[0].NextHop }
  if ('__NET__' -eq '1') {
    $r.internet = P '1.1.1.1'
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try { [void][System.Net.Dns]::GetHostAddresses('www.microsoft.com'); $r.dns_ms = $sw.ElapsedMilliseconds; $r.dns_ok = $true } catch { $r.dns_ok = $false; $r.dns_error = $_.Exception.Message }
    try { $req = [Net.WebRequest]::Create('http://www.msftconnecttest.com/connecttest.txt'); $req.Timeout = 5000
          $resp = $req.GetResponse(); $r.http_ok = ([int]$resp.StatusCode -eq 200); $resp.Close() } catch { $r.http_ok = $false }
  }
  $r
}
T 'time_sync' {
  $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
  $r = [ordered]@{ type = (RegV $p 'Type'); server = (RegV $p 'NtpServer'); service = $(try { (Get-CimInstance Win32_Service -Filter "Name='W32Time'").State } catch { $null }) }
  if ('__NET__' -eq '1') {
    $target = $(if ($env:LOGONSERVER -and $env:LOGONSERVER -notmatch $env:COMPUTERNAME) { $env:LOGONSERVER.TrimStart('\') } else { 'time.windows.com' })
    $o = & "$env:windir\System32\w32tm.exe" /stripchart /computer:$target /samples:2 /dataonly 2>&1 | Out-String
    $m = [regex]::Matches($o, '([+-]\d+[\.,]\d+)s')
    if ($m.Count) { $r.offset_s = [double]($m[$m.Count - 1].Groups[1].Value.Replace(',', '.')); $r.reference = $target }
  }
  $r
}
TL 'hosts' {
  $f = "$env:windir\System32\drivers\etc\hosts"
  @(Get-Content -LiteralPath $f -ErrorAction Stop | Where-Object { $_ -match '^\s*[^#\s]' } | ForEach-Object { $_.Trim() } | Select-Object -First 50)
}
T 'proxy' {
  $p = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
  [ordered]@{ enabled = (RegV $p 'ProxyEnable'); server = (RegV $p 'ProxyServer'); pac = (RegV $p 'AutoConfigURL') }
}
TL 'listening' {
  $names = @{}; Get-Process | ForEach-Object { $names[$_.Id] = $_.ProcessName }
  @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $_.LocalAddress -notmatch '^(127\.|::1)' } |
    Sort-Object LocalPort -Unique | ForEach-Object { [ordered]@{ port = [int]$_.LocalPort; address = $_.LocalAddress; process = $names[[int]$_.OwningProcess] } })
}
TL 'netbios' {
  @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object { [ordered]@{ description = $_.Description; netbios = [int]$_.TcpipNetbiosOptions } })
}
"""

# ---------------------------------------------------------------- sécurité
SECURITY = r"""
T 'defender' {
  $m = Get-MpComputerStatus -ErrorAction Stop
  [ordered]@{ service = [bool]$m.AMServiceEnabled; antivirus = [bool]$m.AntivirusEnabled; realtime = [bool]$m.RealTimeProtectionEnabled;
    mode = "$($m.AMRunningMode)"; sig_age = [int64]$m.AntivirusSignatureAge; sig_date = (D $m.AntivirusSignatureLastUpdated);
    quick_age = [int64]$m.QuickScanAge; full_age = [int64]$m.FullScanAge; tamper = $m.IsTamperProtected; engine = $m.AMEngineVersion;
    behavior = [bool]$m.BehaviorMonitorEnabled; ioav = [bool]$m.IoavProtectionEnabled }
}
TL 'defender_threats' {
  @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddDays(-30) } | Select-Object -First 30 | ForEach-Object {
    [ordered]@{ id = [int64]$_.ThreatID; date = (D $_.InitialDetectionTime); resources = @($_.Resources | Select-Object -First 3); action_ok = [bool]$_.ActionSuccess;
      name = $(try { (Get-MpThreat -ThreatID $_.ThreatID -ErrorAction Stop).ThreatName } catch { $null }) } })
}
TL 'av_products' {
  @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object {
    [ordered]@{ name = $_.displayName; state = [int]$_.productState; exe = $_.pathToSignedProductExe } })
}
TL 'firewall' {
  @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { [ordered]@{ name = "$($_.Name)"; enabled = "$($_.Enabled)"; inbound = "$($_.DefaultInboundAction)" } })
}
TL 'fw_products' {
  @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName FirewallProduct -ErrorAction Stop | ForEach-Object { [ordered]@{ name = $_.displayName; state = [int]$_.productState } })
}
TL 'bitlocker' {
  @(Get-CimInstance -Namespace root\cimv2\Security\MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume -ErrorAction Stop | ForEach-Object {
    $kp = @(); try { $kp = @((Invoke-CimMethod -InputObject $_ -MethodName GetKeyProtectors -Arguments @{ KeyProtectorType = [uint32]0 }).VolumeKeyProtectorID) } catch {}
    [ordered]@{ letter = $_.DriveLetter; protection = [int]$_.ProtectionStatus; conversion = [int]$_.ConversionStatus; method = [int]$_.EncryptionMethod;
      volume_type = [int]$_.VolumeType; protectors = $kp.Count } })
}
T 'registry' {
  $L = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
  $W = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
  $P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
  $TS = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
  $S = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
  [ordered]@{
    smb1_server = (RegV 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1');
    smb1_client_start = (RegV 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start');
    smb_server_signing = (RegV 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature');
    smb_client_signing = (RegV 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature');
    llmnr = (RegV 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast');
    wdigest = (RegV 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential');
    lsa_ppl = (RegV $L 'RunAsPPL'); lm_compat = (RegV $L 'LmCompatibilityLevel'); no_lm_hash = (RegV $L 'NoLMHash');
    restrict_anonymous = (RegV $L 'RestrictAnonymous'); restrict_anonymous_sam = (RegV $L 'RestrictAnonymousSAM');
    uac_lua = (RegV $P 'EnableLUA'); uac_admin_prompt = (RegV $P 'ConsentPromptBehaviorAdmin'); uac_secure_desktop = (RegV $P 'PromptOnSecureDesktop');
    local_account_token_filter = (RegV $P 'LocalAccountTokenFilterPolicy');
    rdp_deny = (RegV $TS 'fDenyTSConnections'); rdp_nla = (RegV "$TS\WinStations\RDP-Tcp" 'UserAuthentication');
    rdp_port = (RegV "$TS\WinStations\RDP-Tcp" 'PortNumber'); rdp_security_layer = (RegV "$TS\WinStations\RDP-Tcp" 'SecurityLayer');
    autologon = (RegV $W 'AutoAdminLogon'); autologon_password_set = [bool](RegV $W 'DefaultPassword'); autologon_user = (RegV $W 'DefaultUserName');
    autorun = (RegV 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun');
    autorun_user = (RegV 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun');
    tls10_server = (RegV "$S\TLS 1.0\Server" 'Enabled'); tls11_server = (RegV "$S\TLS 1.1\Server" 'Enabled');
    ssl3_server = (RegV "$S\SSL 3.0\Server" 'Enabled');
    ps_scriptblock_log = (RegV 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging');
    wsh_enabled = (RegV 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' 'Enabled');
    cached_logons = (RegV $W 'CachedLogonsCount');
    screen_saver_secure = (RegV 'HKCU:\Control Panel\Desktop' 'ScreenSaverIsSecure'); screen_saver_timeout = (RegV 'HKCU:\Control Panel\Desktop' 'ScreenSaveTimeOut');
    inactivity_timeout = (RegV $P 'InactivityTimeoutSecs');
    laps_legacy = (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd'); laps = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS');
    smartscreen = (RegV 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen');
    print_spooler = $(try { (Get-CimInstance Win32_Service -Filter "Name='Spooler'").State } catch { $null });
    remote_registry = $(try { (Get-CimInstance Win32_Service -Filter "Name='RemoteRegistry'").State } catch { $null })
  }
}
T 'smb_server' {
  $c = Get-SmbServerConfiguration -ErrorAction Stop
  [ordered]@{ smb1 = [bool]$c.EnableSMB1Protocol; signing_required = [bool]$c.RequireSecuritySignature; encrypt = [bool]$c.EncryptData }
}
TL 'local_users' {
  @(Get-LocalUser -ErrorAction Stop | ForEach-Object { [ordered]@{ name = $_.Name; enabled = [bool]$_.Enabled; sid = "$($_.SID)";
    password_required = [bool]$_.PasswordRequired; password_expires = (D $_.PasswordExpires); password_last_set = (D $_.PasswordLastSet);
    last_logon = (D $_.LastLogon); source = "$($_.PrincipalSource)" } })
}
TL 'admins' {
  $r = @()
  try { $r = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { [ordered]@{ name = $_.Name; sid = "$($_.SID)"; class = "$($_.ObjectClass)"; source = "$($_.PrincipalSource)" } }) }
  catch {
    $g = Get-CimInstance Win32_Group -Filter "SID='S-1-5-32-544'"
    $grp = [ADSI]"WinNT://$env:COMPUTERNAME/$($g.Name),group"
    $r = @($grp.psbase.Invoke('Members') | ForEach-Object { $p = $_.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $_, $null)
      $c = $_.GetType().InvokeMember('Class', 'GetProperty', $null, $_, $null); [ordered]@{ name = ($p -replace '^WinNT://', '' -replace '/', '\'); sid = $null; class = $c; source = $null } })
  }
  $r
}
T 'password_policy' {
  if (-not $IsAdmin) { return $null }
  $f = Join-Path $env:TEMP ("sa_" + [guid]::NewGuid().ToString('N') + '.inf')
  & "$env:windir\System32\secedit.exe" /export /cfg $f /areas SECURITYPOLICY /quiet | Out-Null
  $r = [ordered]@{}
  if (Test-Path $f) { foreach ($l in (Get-Content $f)) { if ($l -match '^\s*(MinimumPasswordLength|PasswordComplexity|MaximumPasswordAge|LockoutBadCount|PasswordHistorySize|ClearTextPassword|LockoutDuration)\s*=\s*(-?\d+)') { $r[$matches[1]] = [int]$matches[2] } }
    Remove-Item $f -Force -ErrorAction SilentlyContinue }
  $r
}
TL 'shares' {
  @(Get-SmbShare -ErrorAction Stop | Where-Object { -not $_.Special -and $_.Name -notmatch '\$$' } | ForEach-Object {
    $s = $_; $acc = @(); try { $acc = @(Get-SmbShareAccess -Name $s.Name -ErrorAction Stop | ForEach-Object { [ordered]@{ account = $_.AccountName; right = "$($_.AccessRight)"; type = "$($_.AccessControlType)" } }) } catch {}
    [ordered]@{ name = $s.Name; path = $s.Path; access = $acc } })
}
TL 'certificates' {
  @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction Stop | ForEach-Object { [ordered]@{ subject = $_.Subject; issuer = $_.Issuer;
    not_after = (D $_.NotAfter); not_before = (D $_.NotBefore); private_key = [bool]$_.HasPrivateKey; thumbprint = $_.Thumbprint;
    eku = @($_.EnhancedKeyUsageList | ForEach-Object { $_.FriendlyName }); self_signed = ($_.Subject -eq $_.Issuer) } })
}
T 'uac_user' { [ordered]@{ user = "$env:USERDOMAIN\$env:USERNAME" } }
"""

COLLECTORS: dict[str, tuple[str, str, int]] = {
    # nom : (libellé, script, délai max en secondes)
    "system": ("Système et matériel", SYSTEM, 90),
    "disks": ("Disques et stockage", DISKS, 120),
    "events": ("Journaux d'événements et fiabilité", EVENTS, 240),
    "updates": ("Mises à jour Windows", UPDATES, 240),
    "software": ("Services, tâches, logiciels et pilotes", SOFTWARE, 180),
    "network": ("Réseau", NETWORK, 120),
    "security": ("Sécurité", SECURITY, 120),
}


def build(name: str, *, days: int = 30, online_updates: bool = True, network_tests: bool = True) -> str:
    _label, body, _t = COLLECTORS[name]
    body = (body.replace("__DAYS__", str(int(days)))
                .replace("__ONLINE__", "1" if online_updates else "0")
                .replace("__NET__", "1" if network_tests else "0"))
    return PRELUDE + body + EPILOGUE
