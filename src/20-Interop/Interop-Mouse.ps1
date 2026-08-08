<#
    Mouse settings via SystemParametersInfo (spec 6.1).

    Applies "Enhance pointer precision" off without requiring a logoff.

    Ordering note that matters: SPIF_UPDATEINIFILE causes SystemParametersInfo
    to write HKCU\Control Panel\Mouse itself. So the manifest must capture the
    pre-change registry values BEFORE the SPI call, and Set-OptRegistryValue
    must run first (the registry values are what persist across logon).

    Interaction with elevation: SystemParametersInfo affects the CALLING user's
    session. If the elevated identity is not the interactive user, the registry
    writes are redirected to HKU\<interactive-sid> while an SPI call would apply
    to the wrong session - so in that case the SPI call is skipped entirely and
    a logoff is flagged instead.
#>

function Get-OptMouseInteropSource {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return @'
using System;
using System.Runtime.InteropServices;

namespace Cs2Opt.Input
{
    public static class Api
    {
        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool SystemParametersInfo(uint uiAction, uint uiParam, IntPtr pvParam, uint fWinIni);

        private const uint SPI_GETMOUSE       = 0x0003;
        private const uint SPI_SETMOUSE       = 0x0004;
        private const uint SPI_GETMOUSESPEED  = 0x0070;
        private const uint SPI_SETMOUSESPEED  = 0x0071;

        private const uint SPIF_UPDATEINIFILE = 0x01;
        private const uint SPIF_SENDCHANGE    = 0x02;

        /// <summary>{ threshold1, threshold2, acceleration }</summary>
        public static int[] GetMouse()
        {
            IntPtr buf = Marshal.AllocHGlobal(sizeof(int) * 3);
            try
            {
                if (!SystemParametersInfo(SPI_GETMOUSE, 0, buf, 0)) return null;
                int[] v = new int[3];
                Marshal.Copy(buf, v, 0, 3);
                return v;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        public static bool SetMouse(int threshold1, int threshold2, int acceleration)
        {
            IntPtr buf = Marshal.AllocHGlobal(sizeof(int) * 3);
            try
            {
                int[] v = new int[] { threshold1, threshold2, acceleration };
                Marshal.Copy(v, 0, buf, 3);
                return SystemParametersInfo(SPI_SETMOUSE, 0, buf, SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        /// <summary>Pointer speed slider, 1..20. 10 is the 6/11 notch (no scaling).</summary>
        public static int GetMouseSpeed()
        {
            IntPtr buf = Marshal.AllocHGlobal(sizeof(int));
            try
            {
                if (!SystemParametersInfo(SPI_GETMOUSESPEED, 0, buf, 0)) return -1;
                return Marshal.ReadInt32(buf);
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        public static bool SetMouseSpeed(int speed)
        {
            // For SPI_SETMOUSESPEED the value is passed IN pvParam itself,
            // not through a pointer to a buffer.
            return SystemParametersInfo(SPI_SETMOUSESPEED, 0, new IntPtr(speed), SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
        }
    }
}
'@
}

function Get-OptMouseState {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    if (-not ('Cs2Opt.Input.Api' -as [type])) { return $null }

    $v = [Cs2Opt.Input.Api]::GetMouse()
    if (-not $v) { return $null }

    return @{
        Threshold1   = [int]$v[0]
        Threshold2   = [int]$v[1]
        Acceleration = [int]$v[2]
        Speed        = [int][Cs2Opt.Input.Api]::GetMouseSpeed()
    }
}
