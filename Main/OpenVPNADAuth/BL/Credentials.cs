using System;
using System.Diagnostics;

namespace OpenVPNADAuth.BL
{
    internal class Credentials
    {
        internal string UserName { get; private set; }

        internal string Pass { get; private set; }

        internal bool HasData { get { return (UserName.Length > 0 && Pass.Length > 0); } }

        internal Credentials(params string[] data)
        {
            UserName = data.Length > 0 && data[0] != null ? data[0] : string.Empty;
            Pass = data.Length > 1 && data[1] != null ? data[1] : string.Empty;
        }
    }
}
