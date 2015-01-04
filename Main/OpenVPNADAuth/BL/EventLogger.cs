using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OpenVPNADAuth.BL
{
    /// <summary>
    /// Internal event logger class which is used to forward the errors to the event log.
    /// </summary>
    internal static class EventLogger
    {
        private static readonly object Lock = new object();

        private static volatile bool _logAllEvents = false;

        public static bool LogAll
        {
            get { return _logAllEvents; }
            set { _logAllEvents = value; }
        }

        private static EventLog _log;

        private static string SourceName
        {
            get { return "Application"; }
        }

        private static EventLog Log
        {
            get
            {
                if (_log == null)
                {
                    lock (Lock)
                    {
                        if (_log == null)
                        {
                            if (!EventLog.SourceExists(SourceName))
                            {
                                EventLog.CreateEventSource(SourceName, string.Empty);
                            }

                            _log = new EventLog(string.Empty);
                            _log.Source = SourceName;
                        }
                    }
                }
                return _log;
            }
        }
        internal static void Warn(string message)
        {
            if (LogAll)
            {
                Log.WriteEntry(message, EventLogEntryType.Warning);
            }
        }

        internal static void Fatal(Exception message)
        {
            Log.WriteEntry(message.ToString(), EventLogEntryType.Error);
        }

        internal static void Info(string message)
        {
            if (LogAll)
            {
                Log.WriteEntry(message, EventLogEntryType.Information);
            }
        }
    }
}
