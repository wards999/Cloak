# Mount a test drive with cloak-winmount and check what only a real mount can:
# that moving an item out of a folder tells that folder (Explorer refreshes on
# it), and that many moves at once, with folders being watched, never hang the
# drive. v0.6.3 hung here (a WinFsp 2.1 deadlock); see winmount.rs.
#
#   powershell -File tests/winmount_stress.ps1 -Bin target/release [-Seconds 20]
#
# Needs WinFsp installed. Exits non-zero on a failure or a hang.
param([Parameter(Mandatory = $true)][string]$Bin, [int]$Seconds = 20)
$ErrorActionPreference = "Stop"
$Bin = (Resolve-Path $Bin).Path
$env:PATH = "${env:ProgramFiles(x86)}\WinFsp\bin;$env:PATH"

$work = Join-Path ([IO.Path]::GetTempPath()) ("cloak-stress-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$drive = Join-Path $work "drive"
$env:CLOAK_PASSPHRASE = "stress-test"
& "$Bin\cloak.exe" create $drive | Out-Null
if ($LASTEXITCODE) { throw "couldn't create the test drive" }

$letter = ([char[]](68..90) | Where-Object { -not (Test-Path "${_}:\") } | Select-Object -Last 1) + ":"
$psi = New-Object Diagnostics.ProcessStartInfo "$Bin\cloak-winmount.exe", "`"$drive`" $letter"
$psi.UseShellExecute = $false
$psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
$mount = [Diagnostics.Process]::Start($psi)
for ($i = 0; $i -lt 60 -and -not (Test-Path "$letter\"); $i++) { Start-Sleep -Milliseconds 250 }
if (-not (Test-Path "$letter\")) { throw "the drive didn't mount: $($mount.StandardError.ReadToEnd())" }

Add-Type -TypeDefinition @"
using System; using System.IO; using System.Threading; using System.Threading.Tasks;
public static class Stress {
    public static long Moves, LastMove;

    // Move dir\f.txt into dir\Sub and say whether dir heard of it.
    public static bool MoveOutIsNoticed(string dir) {
        Directory.CreateDirectory(Path.Combine(dir, "Sub"));
        File.WriteAllText(Path.Combine(dir, "f.txt"), "x");
        using (var w = new FileSystemWatcher(dir)) {
            w.NotifyFilter = NotifyFilters.FileName;
            var heard = Task.Run(() => w.WaitForChanged(WatcherChangeTypes.Deleted, 3000));
            Thread.Sleep(200);
            File.Move(Path.Combine(dir, "f.txt"), Path.Combine(dir, "Sub", "f.txt"));
            return !heard.Result.TimedOut;
        }
    }

    // Threads moving files back and forth between two folders each.
    public static Task Start(string root, int threads, int seconds) {
        var end = DateTime.UtcNow.AddSeconds(seconds);
        var all = new Task[threads];
        for (int t = 0; t < threads; t++) {
            int id = t;
            all[t] = Task.Factory.StartNew(() => {
                string a = Path.Combine(root, "A" + id), b = Path.Combine(root, "B" + id);
                Directory.CreateDirectory(a); Directory.CreateDirectory(b);
                for (int i = 0; i < 20; i++) File.WriteAllText(Path.Combine(a, "f" + i + ".txt"), "x");
                var rnd = new Random(id);
                while (DateTime.UtcNow < end) {
                    int i = rnd.Next(20);
                    string pa = Path.Combine(a, "f" + i + ".txt"), pb = Path.Combine(b, "f" + i + ".txt");
                    try { if (File.Exists(pa)) File.Move(pa, pb); else File.Move(pb, pa); } catch (IOException) {}
                    Interlocked.Increment(ref Moves);
                    Interlocked.Exchange(ref LastMove, Environment.TickCount);
                }
            }, TaskCreationOptions.LongRunning);
        }
        return Task.WhenAll(all);
    }
}
"@

$failed = $null
try {
    # 1. A move out of a folder tells that folder.
    if (-not [Stress]::MoveOutIsNoticed("$letter\N")) {
        $failed = "moving a file out of a folder didn't tell that folder"
    }

    # 2. Many moves at once, with every folder watched, never hang.
    if (-not $failed) {
        $job = [Stress]::Start("$letter\", 8, $Seconds)
        Start-Sleep -Milliseconds 800
        $watchers = foreach ($k in 0..7) {
            foreach ($n in "A$k", "B$k") {
                if (Test-Path "$letter\$n") {
                    $x = New-Object IO.FileSystemWatcher "$letter\$n"
                    $x.EnableRaisingEvents = $true
                    $x
                }
            }
        }
        while (-not $job.IsCompleted) {
            Start-Sleep -Milliseconds 500
            if ([Stress]::LastMove -and ([Environment]::TickCount - [Stress]::LastMove) -gt 15000) {
                $failed = "the drive hung: no move finished for 15 s"
                break
            }
        }
        $watchers | ForEach-Object { $_.Dispose() }
        if (-not $failed -and $job.IsFaulted) { $failed = "the moves failed: $($job.Exception.InnerException.Message)" }
        Write-Host "moves: $([Stress]::Moves)"
        if (-not $failed -and [Stress]::Moves -lt 100) { $failed = "only $([Stress]::Moves) moves ran" }
    }
} finally {
    if ($failed -like "the drive hung*") {
        $mount.Kill()
    } else {
        $mount.StandardInput.Close()
        if (-not $mount.WaitForExit(15000)) {
            if (-not $failed) { $failed = "the drive didn't unmount" }
            $mount.Kill()
        }
    }
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
if ($failed) { Write-Error $failed; exit 1 }
Write-Host "ok"
