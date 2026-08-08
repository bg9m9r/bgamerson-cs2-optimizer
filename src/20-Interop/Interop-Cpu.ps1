<#
    CPU topology via GetLogicalProcessorInformationEx.

    This exists because deriving topology from a microarchitecture lookup table
    is unsafe. The reference machine is a Ryzen 7 9850X3D reporting
    "AMD64 Family 26 Model 68" - a part that is in nobody's hardcoded table.
    Spec 1.5.3 says unknown means skip, and a table miss would therefore skip
    section 6.4 on a machine where it is perfectly appropriate.

    Two facts are read straight from the OS instead:

      HasHybridTopology - distinct EfficiencyClass values across processor
                          cores. Intel P/E parts report more than one; every
                          AMD desktop part reports a single class. No table.

      CcdCount          - number of distinct L3 cache instances. On Ryzen each
                          CCD carries its own L3, so this is a direct read of
                          the thing section 6.4 actually cares about, rather
                          than an inference from core count.
#>

function Get-OptCpuInteropSource {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Cs2Opt.Cpu
{
    public class Topology
    {
        public int  PhysicalCores;
        public int  LogicalCores;
        public int  PackageCount;
        public int  L3CacheCount;      // == CCD count on AMD Ryzen
        public long L3CacheBytesMax;
        public int  EfficiencyClassCount;
        public bool IsHybrid;
        public bool Succeeded;
        public string Error;
    }

    public static class Api
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetLogicalProcessorInformationEx(
            int relationshipType, IntPtr buffer, ref int returnedLength);

        private const int RelationProcessorCore = 0;
        private const int RelationCache         = 2;
        private const int RelationProcessorPackage = 3;
        private const int RelationAll           = 0xffff;

        private const int ERROR_INSUFFICIENT_BUFFER = 122;

        private static int PopCount(ulong v)
        {
            int c = 0;
            while (v != 0) { v &= (v - 1); c++; }
            return c;
        }

        public static Topology Get()
        {
            Topology t = new Topology();
            IntPtr buffer = IntPtr.Zero;
            try
            {
                int len = 0;
                GetLogicalProcessorInformationEx(RelationAll, IntPtr.Zero, ref len);
                if (len <= 0)
                {
                    t.Error = "GetLogicalProcessorInformationEx returned zero length";
                    return t;
                }

                buffer = Marshal.AllocHGlobal(len);
                if (!GetLogicalProcessorInformationEx(RelationAll, buffer, ref len))
                {
                    t.Error = "GetLogicalProcessorInformationEx failed, win32=" + Marshal.GetLastWin32Error();
                    return t;
                }

                HashSet<byte> efficiencyClasses = new HashSet<byte>();
                long offset = 0;

                while (offset < len)
                {
                    IntPtr rec = new IntPtr(buffer.ToInt64() + offset);
                    int relationship = Marshal.ReadInt32(rec, 0);
                    int size         = Marshal.ReadInt32(rec, 4);
                    if (size <= 0) break;

                    if (relationship == RelationProcessorCore)
                    {
                        t.PhysicalCores++;

                        // PROCESSOR_RELATIONSHIP:
                        //   +8  BYTE Flags
                        //   +9  BYTE EfficiencyClass
                        //   +10 BYTE Reserved[20]
                        //   +30 WORD GroupCount
                        //   +32 GROUP_AFFINITY GroupMask[]   (16 bytes each on x64)
                        byte efficiency = Marshal.ReadByte(rec, 9);
                        efficiencyClasses.Add(efficiency);

                        short groupCount = Marshal.ReadInt16(rec, 30);
                        for (int g = 0; g < groupCount; g++)
                        {
                            ulong mask = (ulong)Marshal.ReadIntPtr(rec, 32 + (g * 16)).ToInt64();
                            t.LogicalCores += PopCount(mask);
                        }
                    }
                    else if (relationship == RelationProcessorPackage)
                    {
                        t.PackageCount++;
                    }
                    else if (relationship == RelationCache)
                    {
                        // CACHE_RELATIONSHIP:
                        //   +8  BYTE Level
                        //   +9  BYTE Associativity
                        //   +10 WORD LineSize
                        //   +12 DWORD CacheSize
                        //   +16 DWORD Type
                        byte level = Marshal.ReadByte(rec, 8);
                        if (level == 3)
                        {
                            t.L3CacheCount++;
                            uint cacheSize = (uint)Marshal.ReadInt32(rec, 12);
                            if (cacheSize > t.L3CacheBytesMax) t.L3CacheBytesMax = cacheSize;
                        }
                    }

                    offset += size;
                }

                t.EfficiencyClassCount = efficiencyClasses.Count;
                t.IsHybrid   = efficiencyClasses.Count > 1;
                t.Succeeded  = true;
                return t;
            }
            catch (Exception ex)
            {
                t.Error = ex.Message;
                return t;
            }
            finally
            {
                if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            }
        }
    }
}
'@
}

function Get-OptCpuTopology {
    <#
        Returns a plain hashtable (never a CIM/interop object) so it drops
        straight into the serializable profile.

        On failure every field is $null rather than a guess - the caller must
        treat that as "unknown", which per spec 1.5.3 means skip.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $unknown = @{
        PhysicalCores        = $null
        LogicalCores         = $null
        PackageCount         = $null
        CcdCount             = $null
        L3CacheBytesMax      = $null
        EfficiencyClassCount = $null
        IsHybrid             = $null
        Source               = 'unavailable'
    }

    if (-not ('Cs2Opt.Cpu.Api' -as [type])) { return $unknown }

    $t = [Cs2Opt.Cpu.Api]::Get()
    if (-not $t -or -not $t.Succeeded) { return $unknown }

    return @{
        PhysicalCores        = [int]$t.PhysicalCores
        LogicalCores         = [int]$t.LogicalCores
        PackageCount         = [int]$t.PackageCount
        # L3 instances == CCDs on Ryzen. Reported as $null rather than 0 when
        # the OS gave us nothing, so the gate sees "unknown", not "one CCD".
        CcdCount             = $(if ($t.L3CacheCount -gt 0) { [int]$t.L3CacheCount } else { $null })
        L3CacheBytesMax      = [long]$t.L3CacheBytesMax
        EfficiencyClassCount = [int]$t.EfficiencyClassCount
        IsHybrid             = [bool]$t.IsHybrid
        Source               = 'GetLogicalProcessorInformationEx'
    }
}
