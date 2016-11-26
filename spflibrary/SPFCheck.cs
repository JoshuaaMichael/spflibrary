using System;
using spflibrary.enums;
using System.Collections.Generic;

/*	TODO: 
 *		- Write the 'include' mechanism
 *		- Unit tests, on everything
 *		- Make all wording match the website
 *		- Clean it up, resharper or something
 *		- Re-write the documentation
 *		- Remove all the interfaces
 *		- Support case insensitivity
 *		- Thread safe the dictionary
 *		- Solve starting with mechanism issue
 */


namespace spflibrary
{
	public static class SPFCheck
	{
		private static Dictionary<char, SPFQualifier> charSPFQualifier;
		private static Dictionary<SPFMechanism, string> mechanismStartsWith;
		private static Dictionary<string, SPFMechanism> startsWithMechanism; //Reverse dictionary

		
		public static SPFResult PerformCheck(string ipAddress, string clientIp, string domain)
		{
			SetupDictionaries(); //Cheaper here then in every dict lookup call

			
			//does is start with v=spf1, that's all I can take, soz brah
			//split it all up on white space
			//for each value, check if it matches the heading of one of the mechanisms
			//if it does, check if it matches, if it does, return it's qualifier
			throw new NotImplementedException();
		}

		private static bool MatchAllMechanism(string spfRecordMechanism)
		{
			return true;
		}

		private static bool MatchIP4Mechanism(string spfRecordMechanism, string clientIp4)
		{
			string ip4Range = spfRecordMechanism.Substring(3);

			return IPTool.ContainsIPv4(clientIp4, ip4Range);
		}

		private static bool MatchIP6Mechanism(string spfRecordMechanism, string clientIp6)
		{
			string ip6Range = spfRecordMechanism.Substring(3);

			return IPTool.ContainsIPv6(clientIp6, ip6Range);
		}

		public static bool MatchAMechanism(string spfRecordMechanism, string clientIp, string currentDomain = "")
		{
			string cidr = "";
			string domainToCheck = currentDomain;

			if(spfRecordMechanism.Length > 1 && spfRecordMechanism[1] == '/')
			{
				cidr = spfRecordMechanism.Substring(1);
			}

			if (spfRecordMechanism.Length > 1 && spfRecordMechanism[1] == ':') //Not just the current domain(and possible qualifier)
			{
				domainToCheck = spfRecordMechanism.Substring(2);

				int CIDRIndex = domainToCheck.LastIndexOf("/");

				if (CIDRIndex != -1) //We have a subnet attached
				{
					cidr = domainToCheck.Substring(CIDRIndex);
					domainToCheck = domainToCheck.Substring(0, CIDRIndex);
				}
			}

			List<string> ips = DNSLookup.LookupARecords(domainToCheck);

			foreach(string ip in ips)
			{
				if (IPTool.ContainsIPv4(clientIp, ip + cidr))
				{
					return true;
				}
			}

			return false;
		}

		public static bool MatchMXMechanism(string spfRecordMechanism, string clientIp, string currentDomain = "")
		{
			string cidr = "";
			string domainToCheck = currentDomain;

			if (spfRecordMechanism.Length > 2 && spfRecordMechanism[2] == '/')
			{
				cidr = spfRecordMechanism.Substring(2);
			}

			if (spfRecordMechanism.Length > 2 && spfRecordMechanism[2] == ':') //Not just the current domain(and possible qualifier)
			{
				domainToCheck = spfRecordMechanism.Substring(3);

				int CIDRIndex = domainToCheck.LastIndexOf("/");

				if (CIDRIndex != -1) //We have a subnet attached
				{
					cidr = domainToCheck.Substring(CIDRIndex);
					domainToCheck = domainToCheck.Substring(0, CIDRIndex);
				}
			}

			List<string> domains = DNSLookup.LookupMXRecords(domainToCheck);
			List<string> ips = DNSLookup.LookupARecords(domains);

			foreach (string ip in ips)
			{
				if (IPTool.ContainsIPv4(clientIp, ip + cidr))
				{
					return true;
				}
			}

			return false;
		}

		public static bool MatchPTRMechanism(string spfRecordMechanism, string clientIp, string currentDomain = "")
		{
			string domainToCheck = currentDomain;

			if (spfRecordMechanism.Length > 3 && spfRecordMechanism.IndexOf(":") == 4)
			{
				domainToCheck = spfRecordMechanism.Substring(4);
			}

			List<string> hostnames = DNSLookup.LookupPTRRecords(clientIp);
			List<string> validHostnames = new List<string>();

			foreach(string hostname in hostnames)
			{
				List<string> ips = DNSLookup.LookupARecords(hostname);
				foreach(string ip in ips)
				{
					if (IPTool.IsSameIP(clientIp, ip))
					{
						validHostnames.Add(hostname);
					}
				}
			}

			foreach (string hostname in validHostnames)
			{
				if(hostname.EndsWith(domainToCheck))
				{
					return true;
				}
			}

			return false;
		}

		public static bool MatchExistsMechanism(string spfRecordMechanism)
		{
			string domain = spfRecordMechanism.Substring(7);

			List<string> ips = DNSLookup.LookupARecords(domain);

			return (ips.Count > 0);
		}

		private static SPFQualifier ExtractQualifier(string spfRecordMechanism, SPFMechanism spfMechanism)
		{
			if(spfMechanism == SPFMechanism.INCLUDE)
			{
				throw new NotImplementedException("Not yet implemented");
			}

			return ExtractQualifier(spfRecordMechanism, LookupStartsWith(spfMechanism));
		}

		private static SPFQualifier ExtractQualifier(string spfRecordMechanism, string startsWith)
		{
			int index = spfRecordMechanism.IndexOf(startsWith);
			if (index == 0)
			{		
				return SPFQualifier.PASS; //The default qualifier is "+", i.e. "Pass"
			}
			else if (index == 1)
			{
				SPFQualifier value;
				if (charSPFQualifier.TryGetValue(spfRecordMechanism[0], out value))
				{
					return value;
				}
			}
			throw new ArgumentException("Invalid SPF mechanism qualifier");
		}

		private static void SetupDictionaries()
		{
			if (mechanismStartsWith == null || startsWithMechanism == null || charSPFQualifier == null)
			{
				mechanismStartsWith = new Dictionary<SPFMechanism, string>();

				mechanismStartsWith.Add(SPFMechanism.ALL, "all");
				mechanismStartsWith.Add(SPFMechanism.IP4, "ip4");
				mechanismStartsWith.Add(SPFMechanism.IP6, "ip6");
				mechanismStartsWith.Add(SPFMechanism.A, "a");
				mechanismStartsWith.Add(SPFMechanism.MX, "mx");
				mechanismStartsWith.Add(SPFMechanism.PTR, "ptr");
				mechanismStartsWith.Add(SPFMechanism.EXISTS, "exists");
				mechanismStartsWith.Add(SPFMechanism.INCLUDE, "include");

				startsWithMechanism = new Dictionary<string, SPFMechanism>();

				foreach (KeyValuePair<SPFMechanism, string> pair in mechanismStartsWith)
				{
					startsWithMechanism.Add(pair.Value, pair.Key);
				}

				charSPFQualifier = new Dictionary<char, SPFQualifier>();

				charSPFQualifier.Add('+', SPFQualifier.PASS);
				charSPFQualifier.Add('-', SPFQualifier.FAIL);
				charSPFQualifier.Add('~', SPFQualifier.SOFT_FAIL);
				charSPFQualifier.Add('?', SPFQualifier.NEUTRAL);
			}
		}

		private static string LookupStartsWith(SPFMechanism mechanism)
		{
			string value;
			if (!mechanismStartsWith.TryGetValue(mechanism, out value))
			{
				return "";
			}
			return value;
		}

		private static SPFMechanism LookupMechanism(string startsWith)
		{
			SPFMechanism value;
			if (!startsWithMechanism.TryGetValue(startsWith, out value))
			{
				return SPFMechanism.UNKNOWN;
			}
			return value;
		}

	}
}
