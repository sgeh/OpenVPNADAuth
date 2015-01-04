using System;
using System.Configuration;
using System.Diagnostics;

namespace OpenVPNADAuth
{
    /// <summary>
    /// Provides a static proxy for all configuration settings required by the OpenVPNADAuth application.
    /// More information about the settings can be obtained in the App.config file.
    /// </summary>
    internal static class Config
    {
        internal static string AdController { get { return ConfigurationManager.AppSettings["AdController"]; } }

        internal static string AdDomain { get { return ConfigurationManager.AppSettings["AdDomain"]; } }

        internal static string LdapPath { get { return ConfigurationManager.AppSettings["LdapPath"]; } }

        internal static string Group { get { return ConfigurationManager.AppSettings["Group"]; } }

        internal static bool EnableLogging { get { return (ConfigurationManager.AppSettings["EnableLogging"] == "true"); } }
    }
}
