<#
    Display enumeration and refresh-rate enforcement (spec 3.8).

    ALL struct marshalling lives inside C#; the surface exposed to PowerShell
    is classes with primitive fields only. This is empirical, not stylistic:
    PowerShell's boxed-struct [ref] marshalling is unreliable here - through an
    identical pattern, EnumDisplaySettingsEx worked while EnumDisplayDevices
    silently returned false. Moving the whole enumeration into C# returned all
    adapters correctly, with PCI DeviceIds.

    Uses the W entry points with CharSet.Unicode throughout. This also fixes
    DEVMODE sizing: the struct is 156 bytes under Ansi and 220 under Unicode,
    and a wrong dmSize makes EnumDisplaySettings fail in confusing ways.
#>

function Get-OptDisplayInteropSource {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Cs2Opt.Display
{
    public class DisplayAdapter
    {
        public string DeviceName;
        public string DeviceString;
        public string DeviceId;
        public bool   IsPrimary;
        public bool   IsAttached;
    }

    public class DisplayMode
    {
        public string Device;
        public int Width;
        public int Height;
        public int Bpp;
        public int Hz;
    }

    public class ChangeResult
    {
        public int    Code;
        public string CodeName;
        public bool   TestPassed;
        public bool   Applied;
        public string Message;
    }

    public static class Api
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DEVMODE
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string dmDeviceName;
            public short dmSpecVersion;
            public short dmDriverVersion;
            public short dmSize;
            public short dmDriverExtra;
            public int   dmFields;
            public int   dmPositionX;
            public int   dmPositionY;
            public int   dmDisplayOrientation;
            public int   dmDisplayFixedOutput;
            public short dmColor;
            public short dmDuplex;
            public short dmYResolution;
            public short dmTTOption;
            public short dmCollate;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string dmFormName;
            public short dmLogPixels;
            public int   dmBitsPerPel;
            public int   dmPelsWidth;
            public int   dmPelsHeight;
            public int   dmDisplayFlags;
            public int   dmDisplayFrequency;
            public int   dmICMMethod;
            public int   dmICMIntent;
            public int   dmMediaType;
            public int   dmDitherType;
            public int   dmReserved1;
            public int   dmReserved2;
            public int   dmPanningWidth;
            public int   dmPanningHeight;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DISPLAY_DEVICE
        {
            public int cb;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]  public string DeviceName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceString;
            public int StateFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceID;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceKey;
        }

        [DllImport("user32.dll", CharSet = CharSet.Unicode, EntryPoint = "EnumDisplayDevicesW")]
        private static extern bool EnumDisplayDevices(string lpDevice, uint iDevNum, ref DISPLAY_DEVICE lpDisplayDevice, uint dwFlags);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, EntryPoint = "EnumDisplaySettingsExW")]
        private static extern bool EnumDisplaySettingsEx(string lpszDeviceName, int iModeNum, ref DEVMODE lpDevMode, uint dwFlags);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, EntryPoint = "ChangeDisplaySettingsExW")]
        private static extern int ChangeDisplaySettingsEx(string lpszDeviceName, ref DEVMODE lpDevMode, IntPtr hwnd, uint dwflags, IntPtr lParam);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, EntryPoint = "ChangeDisplaySettingsExW")]
        private static extern int ChangeDisplaySettingsExApply(string lpszDeviceName, IntPtr lpDevMode, IntPtr hwnd, uint dwflags, IntPtr lParam);

        private const int  ENUM_CURRENT_SETTINGS = -1;
        private const uint CDS_UPDATEREGISTRY    = 0x00000001;
        private const uint CDS_TEST              = 0x00000002;
        private const uint CDS_GLOBAL            = 0x00000008;

        private const int DM_BITSPERPEL       = 0x00040000;
        private const int DM_PELSWIDTH        = 0x00080000;
        private const int DM_PELSHEIGHT       = 0x00100000;
        private const int DM_DISPLAYFREQUENCY = 0x00400000;

        private const int DISPLAY_DEVICE_ATTACHED_TO_DESKTOP = 0x00000001;
        private const int DISPLAY_DEVICE_PRIMARY_DEVICE      = 0x00000004;

        private static DEVMODE NewDevMode()
        {
            DEVMODE dm = new DEVMODE();
            dm.dmDeviceName = new string('\0', 32);
            dm.dmFormName   = new string('\0', 32);
            dm.dmSize       = (short)Marshal.SizeOf(typeof(DEVMODE));
            return dm;
        }

        public static List<DisplayAdapter> GetAdapters()
        {
            List<DisplayAdapter> list = new List<DisplayAdapter>();
            uint i = 0;
            while (true)
            {
                DISPLAY_DEVICE dd = new DISPLAY_DEVICE();
                dd.cb = Marshal.SizeOf(typeof(DISPLAY_DEVICE));
                if (!EnumDisplayDevices(null, i, ref dd, 0)) break;

                DisplayAdapter a = new DisplayAdapter();
                a.DeviceName   = dd.DeviceName;
                a.DeviceString = dd.DeviceString;
                a.DeviceId     = dd.DeviceID;
                a.IsPrimary    = (dd.StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE) != 0;
                a.IsAttached   = (dd.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP) != 0;
                list.Add(a);
                i++;
                if (i > 64) break;
            }
            return list;
        }

        /// <summary>Monitor friendly name behind an adapter (EnumDisplayDevices second level).</summary>
        public static string GetMonitorName(string device)
        {
            DISPLAY_DEVICE dd = new DISPLAY_DEVICE();
            dd.cb = Marshal.SizeOf(typeof(DISPLAY_DEVICE));
            if (EnumDisplayDevices(device, 0, ref dd, 0)) return dd.DeviceString;
            return null;
        }

        public static DisplayMode GetCurrentMode(string device)
        {
            DEVMODE dm = NewDevMode();
            if (!EnumDisplaySettingsEx(device, ENUM_CURRENT_SETTINGS, ref dm, 0)) return null;

            DisplayMode m = new DisplayMode();
            m.Device = device;
            m.Width  = dm.dmPelsWidth;
            m.Height = dm.dmPelsHeight;
            m.Bpp    = dm.dmBitsPerPel;
            m.Hz     = dm.dmDisplayFrequency;
            return m;
        }

        public static List<DisplayMode> GetModes(string device)
        {
            List<DisplayMode> list = new List<DisplayMode>();
            int i = 0;
            while (true)
            {
                DEVMODE dm = NewDevMode();
                if (!EnumDisplaySettingsEx(device, i, ref dm, 0)) break;

                DisplayMode m = new DisplayMode();
                m.Device = device;
                m.Width  = dm.dmPelsWidth;
                m.Height = dm.dmPelsHeight;
                m.Bpp    = dm.dmBitsPerPel;
                m.Hz     = dm.dmDisplayFrequency;
                list.Add(m);
                i++;
                if (i > 8192) break;
            }
            return list;
        }

        private static string CodeName(int c)
        {
            switch (c)
            {
                case  1: return "DISP_CHANGE_RESTART";
                case  0: return "DISP_CHANGE_SUCCESSFUL";
                case -1: return "DISP_CHANGE_FAILED";
                case -2: return "DISP_CHANGE_BADMODE";
                case -3: return "DISP_CHANGE_NOTUPDATED";
                case -4: return "DISP_CHANGE_BADFLAGS";
                case -5: return "DISP_CHANGE_BADPARAM";
                case -6: return "DISP_CHANGE_BADDUALVIEW";
                default: return "DISP_CHANGE_UNKNOWN(" + c + ")";
            }
        }

        /// <summary>
        /// Sets refresh rate only. Width/height/bpp are pinned to their CURRENT
        /// values and included in dmFields, which is what enforces spec 3.8.5 -
        /// never silently drop resolution or colour depth to reach a higher
        /// refresh. Always CDS_TEST first; testOnly stops there (this is what
        /// -DryRun uses, and it is more informative than skipping because it
        /// reports whether the mode would actually validate).
        /// </summary>
        public static ChangeResult TrySetRefresh(string device, int hz, bool testOnly)
        {
            ChangeResult r = new ChangeResult();

            DEVMODE dm = NewDevMode();
            if (!EnumDisplaySettingsEx(device, ENUM_CURRENT_SETTINGS, ref dm, 0))
            {
                r.Code = -1; r.CodeName = "ENUM_CURRENT_SETTINGS failed"; r.Message = "Could not read current mode";
                return r;
            }

            dm.dmDisplayFrequency = hz;
            dm.dmFields = DM_DISPLAYFREQUENCY | DM_PELSWIDTH | DM_PELSHEIGHT | DM_BITSPERPEL;

            int test = ChangeDisplaySettingsEx(device, ref dm, IntPtr.Zero, CDS_TEST, IntPtr.Zero);
            r.Code       = test;
            r.CodeName   = CodeName(test);
            r.TestPassed = (test == 0);

            if (test != 0 || testOnly)
            {
                r.Message = testOnly ? "test only" : "mode rejected by driver";
                return r;
            }

            int applied = ChangeDisplaySettingsEx(device, ref dm, IntPtr.Zero, CDS_UPDATEREGISTRY | CDS_GLOBAL, IntPtr.Zero);
            r.Code     = applied;
            r.CodeName = CodeName(applied);
            r.Applied  = (applied == 0 || applied == 1);

            if (r.Applied)
            {
                // Commit the pending change set.
                ChangeDisplaySettingsExApply(null, IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero);
            }
            return r;
        }
    }
}
'@
}

function Get-OptDisplayAdapters {
    [CmdletBinding()]
    param()
    # Returns unrolled so the result can be piped into Where-Object directly.
    # Callers needing .Count wrap in @(...).
    if (-not ('Cs2Opt.Display.Api' -as [type])) { return @() }
    return @([Cs2Opt.Display.Api]::GetAdapters())
}

function Get-OptDisplayCurrentMode {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Device)
    if (-not ('Cs2Opt.Display.Api' -as [type])) { return $null }
    return [Cs2Opt.Display.Api]::GetCurrentMode($Device)
}

function Get-OptDisplayMaxRefresh {
    <#
        Max refresh available AT THE CURRENT resolution and colour depth.

        Deliberately not the global max across all modes: many panels expose a
        higher refresh at a lower resolution, and silently switching resolution
        to reach it is exactly what spec 3.8.5 forbids.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)][string]$Device,
        [Parameter(Mandatory)][int]$Width,
        [Parameter(Mandatory)][int]$Height,
        [Parameter(Mandatory)][int]$Bpp
    )

    if (-not ('Cs2Opt.Display.Api' -as [type])) { return 0 }

    $modes = @([Cs2Opt.Display.Api]::GetModes($Device) |
        Where-Object { $_.Width -eq $Width -and $_.Height -eq $Height -and $_.Bpp -eq $Bpp })

    if (-not $modes -or $modes.Count -eq 0) { return 0 }
    return [int](($modes | Measure-Object -Property Hz -Maximum).Maximum)
}
