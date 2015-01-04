using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using OpenVPNADAuth.BL;
using OpenVPNADAuth.Properties;

namespace OpenVPNADAuth
{
    /// <summary>
    /// Provides the static entry point for the console application.
    /// </summary>
    public class Program
    {
        public static int Main(string[] args)
        {
            AuthResult result;
            Credentials credentials = GetCredentials(args);
            EventLogger.LogAll = Config.EnableLogging;

            if (new AdAuth(Config.AdController, Config.AdDomain, Config.LdapPath, Config.Group).TryAuthenticate(credentials, out result))
            {
                EventLogger.Info(
                    string.Format(
                        Resources.LogAuthSucceeded,
                        credentials.UserName));
                return (Environment.ExitCode = 0); // report success to OpenVPN
            }

            EventLogger.Warn(
                string.Format(
                    Resources.LogAuthFailed,
                    credentials.UserName,
                    Enum.GetName(typeof (AuthResult), result)));
            return (Environment.ExitCode = 1); // report auth error
        }

        private static Credentials GetCredentials(string[] args)
        {
            if (args != null
                && args.Length > 0
                && File.Exists(args[0]))
            {
                return new Credentials(File.ReadAllLines(args[0]));
            }
            return new Credentials(args);
        }
    }
}
