using System;
using System.DirectoryServices;

namespace OpenVPNADAuth.BL
{
    /// <summary>
    /// Provides an enumeration with the login status; see <see cref="AdAuth.TryAuthenticate"/>.
    /// </summary>
    internal enum AuthResult
    {
        UnexpectedError = 0,
        NoCredentials,
        UnknownCredentials,
        UserNotFoundInLdapPath,
        GroupNotFoundInLdapPath,
        UserNotAuthorized,
        Succeeded
    }

    /// <summary>
    /// Represents the authentication handler which is used to login into the AD LDAP directory.
    /// </summary>
    internal class AdAuth
    {
        private const string DistinguishedNameProperty = "distinguishedName";
        private const string DomainUserFormat = @"{0}\{1}";
        private const string AdsRootDseFormat = "LDAP://{0}/RootDSE";
        private const string AdsSearchDseFormat = "LDAP://{0}/{1}";
        private const string AdsUserSearchFormat = "(&(objectClass=user)(SAMAccountName={0}))";
        private const string AdsGroupSearchFormat = "(&(objectClass=group)(name={0}))";
        private const string AdsUserAndGroupSearchFormat = "(&(objectClass=group)(name={0})(member={1}))";

        
        private readonly string _adController;
        private readonly string _adDomain;
        private readonly string _ldapPath;
        private readonly string _group;

        private string AdsRootDse
        {
            get { return string.Format(AdsRootDseFormat, _adController); }
        }

        private string AdsSearchDse
        {
            get { return string.Format(AdsSearchDseFormat, _adController, _ldapPath); }
        }

        internal AdAuth(string adController, string adDomain, string ldapPath, string group)
        {
            _adController = (adController ?? "localhost");
            _adDomain = (adDomain ?? ".");
            _ldapPath = (ldapPath ?? string.Empty);
            _group = (group ?? string.Empty);
        }

        internal bool TryAuthenticate(Credentials pass, out AuthResult reason)
        {
            try
            {
                if (pass.HasData)
                {
                    reason = Authenticate(pass);
                    return (reason == AuthResult.Succeeded);
                }
                else
                {
                    reason = AuthResult.NoCredentials;
                    return false;
                }
            }
            catch (Exception e)
            {
                reason = AuthResult.UnexpectedError;
                EventLogger.Fatal(e);
                return false;
            }
        }


        internal AuthResult Authenticate(Credentials pass)
        {
            if (TryLogin(pass))
            {
                using (DirectoryEntry ldapRoot = OpenEntry(pass, AdsSearchDse))
                {
                    string memberDn;

                    if (!SearchUserInDn(ldapRoot, pass, out memberDn))
                    {
                        return AuthResult.UserNotFoundInLdapPath;
                    }

                    if (!SearchGroupInDn(ldapRoot))
                    {
                        return AuthResult.GroupNotFoundInLdapPath;
                    }

                    if (!SearchUserInGroup(ldapRoot, memberDn))
                    {
                        return AuthResult.UserNotAuthorized;
                    }
                    return AuthResult.Succeeded;
                }
            }
            return AuthResult.UnknownCredentials;
        }

        private bool SearchUserInDn(DirectoryEntry ldapRoot, Credentials pass, out string memberDn)
        {
            memberDn = null;

            using (DirectorySearcher userSearcher = new DirectorySearcher(ldapRoot))
            {
                userSearcher.PageSize = 10;
                userSearcher.CacheResults = false;
                userSearcher.SearchScope = SearchScope.Subtree;
                userSearcher.Filter = string.Format(AdsUserSearchFormat, pass.UserName);
                
                SearchResult result = userSearcher.FindOne();

                if (result != null
                    && result.Properties[DistinguishedNameProperty] != null
                    && result.Properties[DistinguishedNameProperty].Count > 0)
                {
                    memberDn = (string)result.Properties[DistinguishedNameProperty][0];
                    return true;
                }
            }
            return false;
        }

        private bool SearchGroupInDn(DirectoryEntry ldapRoot)
        {
            using (DirectorySearcher userSearcher = new DirectorySearcher(ldapRoot))
            {
                userSearcher.PageSize = 10;
                userSearcher.CacheResults = false;
                userSearcher.SearchScope = SearchScope.Subtree;
                userSearcher.Filter = string.Format(AdsGroupSearchFormat, _group);
                return (userSearcher.FindOne() != null);
            }
        }

        private bool SearchUserInGroup(DirectoryEntry ldapRoot, string memberDn)
        {
            using (DirectorySearcher userSearcher = new DirectorySearcher(ldapRoot))
            {
                userSearcher.PageSize = 10;
                userSearcher.CacheResults = false;
                userSearcher.SearchScope = SearchScope.Subtree;
                userSearcher.Filter = string.Format(AdsUserAndGroupSearchFormat, _group, memberDn);
                return (userSearcher.FindOne() != null);
            }
        }

        private DirectoryEntry OpenEntry(Credentials pass, string ads)
        {
            return new DirectoryEntry(
                ads,
                string.Format(DomainUserFormat, _adDomain, pass.UserName),
                pass.Pass,
                AuthenticationTypes.ServerBind | AuthenticationTypes.Encryption);
        }

        private bool TryLogin(Credentials pass)
        {
            try
            {
                using (var ldapRoot = OpenEntry(pass, AdsRootDse))
                {
                    return (ldapRoot.Name != null);
                }
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}
