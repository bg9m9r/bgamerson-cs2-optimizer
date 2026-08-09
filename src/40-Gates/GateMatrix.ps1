<#
    The spec 1.5.4 gating matrix, as data.

    Every hardware-conditional decision in the script lives in this one table.
    Nothing here touches the OS: each row's `When` is a pure predicate over a
    plain profile hashtable, which is what makes all ~45 rows testable against
    synthetic profiles with zero real hardware.

    TRI-STATE IS THE CORE DESIGN POINT.

    `When` returns $true, $false, or $null (indeterminate), and every row states
    an explicit OnIndeterminate policy. Positive predicates are safe on $null
    because `$null -eq $true` is $false. NEGATIVE predicates are the trap:

        { -not $p.CPU.HasHybridTopology }

    evaluates to $true when the field is unknown, i.e. it would APPLY the tweak
    on unidentified hardware - the exact inversion of spec 1.5.3's "unknown
    means skip, not guess". Forcing every row to declare what an unknown means
    turns that rule into something mechanical and testable.

    Kinds:
      Abort      - stop the run entirely
      ForceTier  - clamp the tier
      Skip       - block one or more sections (prefix match: '8' blocks 8.*)
      Capability - switch off a capability enforced at the mutation chokepoints
      Escalate   - raise a section's importance in the report
      Finding    - a problem for the user to fix, NOT a tweak that succeeded
      Manual     - checklist item
      Note       - expectation-setting text only
#>

function Get-OptGateMatrix {
    [CmdletBinding()]
    [OutputType([array])]
    param()

    return , @(

        # ---------------------------------------------------------------- host
        @{
            Id = 'G-VM'; Section = '0'; Title = 'Virtual machine'
            When = { param($p, $o) ConvertTo-OptBool $p.Virtualization.IsVirtualMachine }
            OnIndeterminate = 'Allow'
            Kind = 'Abort'; Severity = 'Critical'
            Reason = 'running in a virtual machine - nothing in this spec is meaningful here'
        }
        @{
            Id = 'G-LAPTOP'; Section = '2'; Title = 'Laptop / battery present'
            When = { param($p, $o) ConvertTo-OptBool $p.Power.IsLaptop }
            OnIndeterminate = 'Allow'
            # Skips 2.1 only, not all of 2.2: the spec's laptop row exempts USB
            # selective suspend ("the whole of 2.2 EXCEPT USB selective
            # suspend"), so the per-setting laptop handling lives inside
            # Section-02 where it can keep that one setting and drop the rest.
            Kind = 'ForceTier'; Effect = @{ Tier = 'Safe'; Skip = @('2.1') }
            Severity = 'Warning'
            Reason = 'laptop detected - Ultimate Performance and core-parking changes are a thermal-throttling trap'
        }

        # ----------------------------------------------------------------- CPU
        @{
            Id = 'G-6.4-HYBRID'; Section = '6.4'; Title = 'IFEO High priority'
            When = { param($p, $o) ConvertTo-OptBool $p.CPU.HasHybridTopology }
            # Unknown blocks: applying High priority on an unidentified hybrid
            # part can land the render thread on E-cores.
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('6.4') }
            Reason = 'Intel P/E hybrid topology - High priority fights Thread Director placement'
        }
        @{
            Id = 'G-6.4-CORES'; Section = '6.4'; Title = 'IFEO High priority'
            When = { param($p, $o)
                if ($null -eq $p.CPU.LogicalCores) { return $null }
                return ([int]$p.CPU.LogicalCores -lt 8)
            }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('6.4') }
            Reason = 'fewer than 8 logical cores - High priority starves audio and input threads'
        }
        @{
            Id = 'G-2.2-CPMINCORES-HYBRID'; Section = '2.2'; Title = 'Core parking minimum'
            When = { param($p, $o) ConvertTo-OptBool $p.CPU.HasHybridTopology }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('2.2.CPMINCORES') }
            Reason = 'hybrid topology - core parking is managed by Thread Director; overriding forces work onto E-cores'
        }
        @{
            Id = 'G-2.2-X3D'; Section = '2.2'; Title = 'Processor idle disable'
            When = { param($p, $o) ConvertTo-OptBool $p.CPU.HasVCache }
            OnIndeterminate = 'Block'
            Kind = 'Note'; Severity = 'Info'
            Reason = 'X3D part - idle-blocking raises the thermal floor and reduces sustained boost residency (IDLEDISABLE stays 0 on every path anyway)'
        }
        @{
            Id = 'G-6.4-AFFINITY'; Section = '6.4'; Title = 'CPU affinity pinning'
            When = { param($p, $o) $true }
            OnIndeterminate = 'Block'
            Kind = 'Note'
            Reason = 'CPU affinity is never set on any hardware - harmful on single-CCD parts, unvalidated on multi-CCD'
        }
        @{
            Id = 'G-AMD-PPM'; Section = '2.2'; Title = 'AMD power model driver'
            When = { param($p, $o)
                if ($p.CPU.Vendor -ne 'AMD') { return $false }
                return ($p.CPU.PpmDriver -ne 'amdppm')
            }
            OnIndeterminate = 'Allow'
            Kind = 'Finding'; Severity = 'Warning'
            Reason = 'AMD CPU without the amdppm power driver loaded - Windows will misapply the power model regardless of what this script sets. Install the AMD chipset driver package.'
        }
        @{
            # Intel counterpart to G-AMD-PPM (spec 1.5.4 and 2.2 both call for
            # it): on a hybrid part without intelppm loaded, Thread Director is
            # not in charge of placement, and every hybrid-related gate premise
            # here rests on it being so.
            Id = 'G-INTEL-PPM'; Section = '2.2'; Title = 'Intel power model driver'
            When = { param($p, $o)
                if ($p.CPU.Vendor -ne 'Intel') { return $false }
                return ($p.CPU.PpmDriver -ne 'intelppm')
            }
            OnIndeterminate = 'Allow'
            Kind = 'Finding'; Severity = 'Warning'
            Reason = 'Intel CPU without the intelppm power driver loaded - Thread Director scheduling depends on it. Fix chipset drivers / Windows Update before trusting any scheduling tweak here.'
        }

        # ----------------------------------------------------------------- GPU
        @{
            Id = 'G-3.4-AMD'; Section = '3.4'; Title = 'AMD Adrenalin checklist'
            When = { param($p, $o) ($p.GPU.PrimaryVendor -ne 'AMD') }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('3.4') }
            Reason = 'primary GPU vendor is not AMD'
        }
        @{
            Id = 'G-3.5-NVIDIA'; Section = '3.5'; Title = 'NVIDIA checklist'
            When = { param($p, $o) ($p.GPU.PrimaryVendor -ne 'NVIDIA') }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('3.5') }
            Reason = 'primary GPU vendor is not NVIDIA'
        }
        @{
            Id = 'G-3.6-INTEL'; Section = '3.6'; Title = 'Intel Arc checklist'
            When = { param($p, $o) ($p.GPU.PrimaryVendor -ne 'Intel') }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('3.6') }
            Reason = 'primary GPU vendor is not Intel'
        }
        @{
            Id = 'G-3.1-HAGS-ARC'; Section = '3.1'; Title = 'Hardware-accelerated GPU scheduling'
            When = { param($p, $o) ($p.GPU.PrimaryVendor -eq 'Intel') }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('3.1.HwSchMode') }
            Reason = 'Intel Arc - HAGS behaviour is driver-version dependent; leave at driver default'
        }
        @{
            Id = 'G-GPU-UNKNOWN'; Section = '3'; Title = 'GPU vendor unknown'
            When = { param($p, $o) ($p.GPU.PrimaryVendor -eq 'Unknown' -or $null -eq $p.GPU.PrimaryVendor) }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('3.4', '3.5', '3.6') }
            Severity = 'Warning'
            Reason = 'GPU vendor could not be determined - no vendor-specific GPU tweak will be applied'
        }
        @{
            Id = 'G-3.7-IGPU-CABLE'; Section = '3.7'; Title = 'Primary display on integrated GPU'
            When = { param($p, $o) ConvertTo-OptBool $p.Display.PrimaryOnIntegrated }
            OnIndeterminate = 'Allow'
            Kind = 'Finding'; Severity = 'Error'
            Reason = 'the primary display is connected to the motherboard while a discrete GPU is present. This is a cable problem and no registry tweak fixes it - move the cable to the graphics card.'
        }
        @{
            Id = 'G-AMD-ANTILAGPLUS'; Section = '3.4'; Title = 'AMD Anti-Lag+'
            When = { param($p, $o) ($p.GPU.PrimaryVendor -eq 'AMD') }
            OnIndeterminate = 'Allow'
            Kind = 'Note'; Severity = 'Warning'
            Reason = 'never enable Anti-Lag+ - it triggered VAC bans in CS2 (Oct 2023). Standard Anti-Lag and game-integrated Anti-Lag 2 are fine.'
        }

        # ------------------------------------------------------------- display
        @{
            Id = 'G-3.8-REFRESH'; Section = '3.8'; Title = 'Refresh rate enforcement'
            When = { param($p, $o) -not (ConvertTo-OptBool $p.Display.RefreshBelowMax) }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('3.8') }
            Reason = 'every display is already running at its maximum refresh for the current resolution'
        }
        @{
            Id = 'G-REFRESH-LOW'; Section = '3.8'; Title = 'Low refresh expectations'
            When = { param($p, $o)
                if ($null -eq $p.Display.PrimaryMaxRefreshHz) { return $null }
                return ([int]$p.Display.PrimaryMaxRefreshHz -lt 120)
            }
            OnIndeterminate = 'Allow'
            Kind = 'Note'
            Reason = 'primary display is under 120 Hz - latency tweaks here have diminishing returns; they still apply, but set expectations accordingly'
        }
        @{
            Id = 'G-REFRESH-HIGH'; Section = '3.8'; Title = 'High refresh priority'
            When = { param($p, $o)
                if ($null -eq $p.Display.PrimaryMaxRefreshHz) { return $null }
                return ([int]$p.Display.PrimaryMaxRefreshHz -ge 240)
            }
            OnIndeterminate = 'Allow'
            Kind = 'Note'
            Reason = 'high-refresh panel - sections 3.8, 4.1, 6 and 9 dominate here. Section 10 is not a lever: VBS stays on.'
        }

        # -------------------------------------------------------------- memory
        @{
            Id = 'G-5.4.1-RAM'; Section = '5.4.1'; Title = 'Memory compression disable'
            When = { param($p, $o)
                if ($null -eq $p.Memory.TotalMB) { return $null }
                return ([int]$p.Memory.TotalMB -lt 32768)
            }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('5.4.1') }
            Reason = 'under 32 GB RAM - disabling compression trades CPU for pagefile I/O once pressure exists'
        }
        @{
            Id = 'G-5.4.1-COMMIT'; Section = '5.4.1'; Title = 'Memory compression disable'
            When = { param($p, $o)
                if ($null -eq $p.Memory.CommitPercentOfRam) { return $null }
                return ([double]$p.Memory.CommitPercentOfRam -gt 60)
            }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('5.4.1') }
            Severity = 'Warning'
            Reason = 'commit charge is already above 60% of physical RAM at preflight - capacity alone is not enough, headroom is what matters'
        }
        @{
            Id = 'G-5.4.2-RAM'; Section = '5.4.2'; Title = 'Page combining disable'
            When = { param($p, $o)
                if ($null -eq $p.Memory.TotalMB) { return $null }
                return ([int]$p.Memory.TotalMB -lt 16384)
            }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('5.4.2') }
            Reason = 'under 16 GB RAM - page combining is saving you memory you need'
        }
        @{
            Id = 'G-EXPO'; Section = '12'; Title = 'Memory speed'
            When = { param($p, $o) ConvertTo-OptBool $p.Memory.LooksLikeJedecBase }
            OnIndeterminate = 'Allow'
            Kind = 'Finding'; Severity = 'Warning'
            Reason = 'memory appears to be running at JEDEC base speed - EXPO/XMP may not be enabled. This is a firmware setting and is worth more than most of this script.'
        }

        # ------------------------------------------------------------- storage
        @{
            Id = 'G-5.5-HDD'; Section = '5.5'; Title = 'SysMain disable'
            When = { param($p, $o)
                if ($p.Games.Cs2LibraryMediaType -eq 'HDD') { return $true }
                return (ConvertTo-OptBool $p.Storage.HasHdd)
            }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('5.5') }
            Reason = 'spinning disk present - SysMain prefetch genuinely helps HDDs; keep it enabled and move the library instead'
        }
        @{
            Id = 'G-DEFRAG-KEEP'; Section = '8.1'; Title = 'ScheduledDefrag'
            When = { param($p, $o) $true }
            OnIndeterminate = 'Allow'
            Kind = 'Note'
            Reason = 'ScheduledDefrag stays enabled on every storage type - on SSD/NVMe it issues TRIM, on HDD it defragments. Disabling it is actively harmful.'
        }

        # ------------------------------------------------------------- network
        @{
            Id = 'G-7.1-WIRELESS'; Section = '7.1'; Title = 'NIC advanced properties'
            When = { param($p, $o) ConvertTo-OptBool $p.Network.ActiveIsWireless }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('7.1') }
            Severity = 'Warning'
            Reason = 'the active adapter is wireless - power-management keywords behave differently on Wi-Fi and changing them can cause disconnects. Use wired for FACEIT.'
        }
        @{
            Id = 'G-7.1-INBOX'; Section = '7.1'; Title = 'NIC advanced properties'
            When = { param($p, $o) ([string]$p.Network.ActiveDriverProvider -eq 'Microsoft') }
            OnIndeterminate = 'Allow'
            Kind = 'Finding'; Severity = 'Warning'
            Reason = 'the active NIC uses the Microsoft inbox driver, which exposes almost none of these keywords. Installing the vendor driver is the actual fix, not registry edits.'
        }
        @{
            Id = 'G-7-NOADAPTER'; Section = '7'; Title = 'Network tuning'
            When = { param($p, $o) ($null -eq $p.Network.ActiveAdapterName) }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('7.1', '7.3') }
            Severity = 'Warning'
            Reason = 'no active physical adapter carrying the default route could be identified'
        }
        @{
            Id = 'G-7-VPNMETRIC'; Section = '7'; Title = 'Virtual adapter routing ahead of the NIC'
            When = { param($p, $o) ConvertTo-OptBool $p.Network.VirtualAheadOfPhysical }
            OnIndeterminate = 'Allow'
            Kind = 'Finding'; Severity = 'Warning'
            Reason = 'a virtual adapter (VPN/Tailscale/Hyper-V) holds a lower route metric than the physical NIC - that alone can add tens of milliseconds'
        }

        # -------------------------------------------------------------- games
        @{
            Id = 'G-CS2-ABSENT'; Section = '3.3'; Title = 'CS2-dependent sections'
            When = { param($p, $o) -not (ConvertTo-OptBool $p.Games.Cs2Installed) }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('3.3', '6.4', '9.1', '11') }
            Severity = 'Warning'
            Reason = 'CS2 is not installed - every path-dependent tweak is a no-op. Writing IFEO keys for a nonexistent binary would just leave orphans.'
        }

        # ------------------------------------------------ security / anti-cheat
        @{
            Id = 'G-10-VBS'; Section = '10'; Title = 'VBS disable'
            When = { param($p, $o) ConvertTo-OptBool $p.Security.HasKernelAntiCheat }
            # Unknown BLOCKS: never disable VBS when anti-cheat presence is unclear.
            OnIndeterminate = 'Block'
            Kind = 'Capability'; Effect = @{ Capability = @{ HypervisorOff = $false } ; Skip = @('10.4') }
            Reason = 'kernel anti-cheat present - VBS is a dependency, not an optimization target'
        }
        @{
            Id = 'G-10-VBS-OFF'; Section = '10'; Title = 'FACEIT requires VBS'
            When = { param($p, $o)
                if (-not (ConvertTo-OptBool $p.Security.HasFaceitAc)) { return $false }
                $vbs = ConvertTo-OptBool $p.Security.VbsRunning
                if ($null -eq $vbs) { return $null }
                return (-not $vbs)
            }
            OnIndeterminate = 'Allow'
            Kind = 'Finding'; Severity = 'Critical'
            Reason = 'FACEIT AC is installed but VBS is NOT running. This is a blocking compliance problem, not a tweak - you will be denied entry as enforcement waves expand. Set hypervisorlaunchtype to Auto, enable IOMMU in firmware, reboot.'
        }
        @{
            Id = 'G-10-IOMMU-OFF'; Section = '10'; Title = 'FACEIT requires IOMMU'
            When = { param($p, $o)
                if (-not (ConvertTo-OptBool $p.Security.HasFaceitAc)) { return $false }
                $iommu = ConvertTo-OptBool $p.Security.IommuEnabled
                # $null here means "could not confirm", which must NOT be
                # reported as a failure - a false positive sends the user into
                # their BIOS for nothing.
                if ($null -eq $iommu) { return $null }
                return (-not $iommu)
            }
            OnIndeterminate = 'Allow'
            Kind = 'Finding'; Severity = 'Critical'
            Reason = 'FACEIT AC is installed but IOMMU could not be confirmed enabled. Enable VT-d (Intel) or IOMMU/AMD-Vi + SVM (AMD) in firmware.'
        }
        @{
            Id = 'G-10-NOAC'; Section = '10'; Title = 'VBS disable available'
            When = { param($p, $o) -not (ConvertTo-OptBool $p.Security.HasKernelAntiCheat) }
            OnIndeterminate = 'Block'
            Kind = 'Note'; Severity = 'Warning'
            Reason = 'no kernel anti-cheat detected - VBS disable becomes technically available under Experimental, but it is not the default and the security tradeoff is real'
        }
        @{
            Id = 'G-10.4-HVCI'; Section = '10.4'; Title = 'HVCI / Memory Integrity'
            When = { param($p, $o) ConvertTo-OptBool $p.Security.HvciRunning }
            OnIndeterminate = 'Allow'
            Kind = 'Manual'
            Reason = 'HVCI is running and is left exactly as-is. Turning it off is a user-confirmed experiment only - if a future enforcement wave adds an HVCI check, a script-baked assumption becomes a silent lockout.'
        }
        @{
            Id = 'G-SECUREBOOT'; Section = '0'; Title = 'Secure Boot'
            When = { param($p, $o)
                if (-not (ConvertTo-OptBool $p.Security.HasKernelAntiCheat)) { return $false }
                $sb = ConvertTo-OptBool $p.Security.SecureBootEnabled
                if ($null -eq $sb) { return $null }
                return (-not $sb)
            }
            OnIndeterminate = 'Allow'
            Kind = 'Finding'; Severity = 'Critical'
            Reason = 'kernel anti-cheat present but Secure Boot is disabled - TPM 2.0 and Secure Boot are mandatory for all FACEIT players since 25 Nov 2025'
        }
        @{
            Id = 'G-TPM'; Section = '0'; Title = 'TPM 2.0'
            When = { param($p, $o)
                if (-not (ConvertTo-OptBool $p.Security.HasKernelAntiCheat)) { return $false }
                $tpm = ConvertTo-OptBool $p.Security.TpmReady
                if ($null -eq $tpm) { return $null }
                return (-not $tpm)
            }
            OnIndeterminate = 'Allow'
            Kind = 'Finding'; Severity = 'Critical'
            Reason = 'kernel anti-cheat present but TPM is not present/ready - enable fTPM or PTT in firmware'
        }
        @{
            Id = 'G-BITLOCKER'; Section = '4.3'; Title = 'bcdedit-touching sections'
            When = { param($p, $o)
                $bl = ConvertTo-OptBool $p.Security.BitLockerAnyProtected
                if ($null -eq $bl) { return $null }
                if (-not $bl) { return $false }
                # Spec 1.5.4 requires BOTH conditions to unlock bcdedit:
                # -BitLockerAcknowledged AND a recovery protector confirmed
                # present. Acknowledgement without a recovery key is exactly the
                # brick scenario spec 0 warns about - the PCR mismatch fires on
                # reboot and there is no key to type in.
                if (-not [bool]$o.BitLockerAcknowledged) { return $true }
                return ((ConvertTo-OptBool $p.Security.BitLockerRecoveryKeyEscrowed) -ne $true)
            }
            OnIndeterminate = 'Block'
            Kind = 'Capability'; Effect = @{ Capability = @{ BcdEdit = $false } }
            Severity = 'Warning'
            Reason = 'BitLocker protection is on and either -BitLockerAcknowledged was not passed or no recovery-password protector could be confirmed. Boot-configuration changes alter TPM PCR measurements and drop the machine into a recovery-key prompt - without a confirmed key that is a lockout, not an inconvenience. Skipping is deliberate and safer than suspending.'
        }

        # ------------------------------------------------------ virtualization
        @{
            Id = 'G-HYPERV'; Section = '10'; Title = 'hypervisorlaunchtype off'
            When = { param($p, $o) ConvertTo-OptBool $p.Virtualization.BlocksHypervisorOff }
            OnIndeterminate = 'Block'
            Kind = 'Capability'; Effect = @{ Capability = @{ HypervisorOff = $false } }
            Reason = 'Hyper-V / WSL / Docker / Sandbox is in use - disabling the hypervisor would break it'
        }

        # ------------------------------------------------------------ policies
        @{
            Id = 'G-MANAGED'; Section = '8'; Title = 'Group Policy writes'
            When = { param($p, $o) ConvertTo-OptBool $p.OS.IsManaged }
            OnIndeterminate = 'Allow'
            Kind = 'Capability'; Effect = @{ Capability = @{ PolicyWrites = $false } }
            Severity = 'Warning'
            Reason = 'domain / Azure-AD / MDM joined - HKLM\SOFTWARE\Policies writes are reverted by the management channel and may raise compliance alerts. Ask IT instead.'
        }
        @{
            Id = 'G-8.5-NPU'; Section = '8.5'; Title = 'Windows AI surfaces'
            When = { param($p, $o) -not (ConvertTo-OptBool $p.OS.HasNpu) }
            OnIndeterminate = 'Allow'
            Kind = 'Note'
            Reason = 'no NPU - Recall and the on-device AI features are NOT INSTALLED on this machine. The policy keys are still written as future-proofing, but they are not counted as an applied optimization.'
        }
        @{
            Id = 'G-4.3-PRE22H2'; Section = '4.3'; Title = 'GlobalTimerResolutionRequests'
            When = { param($p, $o) -not (ConvertTo-OptBool $p.OS.Is22H2OrLater) }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('4.3.GlobalTimer') }
            Reason = 'pre-22H2 - timer resolution is already global, so this value has nothing to restore'
        }

        # ---------------------------------------------------------------- boot
        @{
            Id = 'G-2.3-DUALBOOT'; Section = '2.3'; Title = 'Fast Startup / hibernation'
            When = { param($p, $o) ConvertTo-OptBool $p.Boot.IsDualBoot }
            OnIndeterminate = 'Allow'
            Kind = 'Escalate'; Effect = @{ Escalate = @('2.3') }
            Severity = 'Warning'
            Reason = 'dual-boot detected - Fast Startup leaves NTFS dirty and risks corruption when the other OS mounts the partition. This is mandatory here, not optional.'
        }
        @{
            Id = 'G-MODERNSTANDBY'; Section = '2.2'; Title = 'Legacy power timeouts'
            When = { param($p, $o) ConvertTo-OptBool $p.Power.SupportsModernStandby }
            OnIndeterminate = 'Allow'
            Kind = 'Note'
            Reason = 'Modern Standby (S0ix) platform - some legacy timeouts are ignored by the platform. They are still applied, but will not be reported as effective without verification.'
        }

        # --------------------------------------------------------- opt-in only
        @{
            Id = 'G-8.8-OPTIN'; Section = '8.8'; Title = 'Inbox app removal'
            When = { param($p, $o) $true }
            OnIndeterminate = 'Block'
            Kind = 'Note'
            Reason = 'report-only in this build. Provisioned Appx removal cannot be reliably rolled back, and it buys disk space, not frames.'
        }
        @{
            Id = 'G-8.9-OPTIN'; Section = '8.9'; Title = 'OneDrive removal'
            When = { param($p, $o) $true }
            OnIndeterminate = 'Block'
            Kind = 'Note'
            Reason = 'report-only in this build. "Local-only content" cannot be reliably distinguished from Files-On-Demand placeholders by file attributes alone.'
        }

        # -------------------------------------------------------------- input
        @{
            Id = 'G-6.1-VENDOR'; Section = '6.1'; Title = 'Peripheral vendor utility'
            When = { param($p, $o) ConvertTo-OptBool $p.Input.HasVendorUtility }
            OnIndeterminate = 'Allow'
            Kind = 'Finding'; Severity = 'Warning'
            Reason = 'a peripheral vendor utility is installed and overrides the Windows mouse settings written here. You must also disable acceleration / angle-snapping inside that utility, or section 6.1 achieves nothing.'
        }
    )
}
