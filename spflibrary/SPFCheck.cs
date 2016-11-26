using System;
using spflibrary.enums;
using System.Collections.Generic;

/*	TODO: 
 *		- Unit tests, on everything
 *		- Make all wording match the website
 *		- Clean it up, resharper or something
 *		- Re-write the documentation
 *		- Remove all the interfaces
 */


namespace spflibrary
{
	public static class SPFCheck
	{
		public static SPFResult PerformCheck(string ipAddress, string clientIp, string domain)
		{
			//does is tart with v=spf1, that's all I can take, soz brah
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
			//string domain = spfRecordMechanism.Substring(3);

			//return IPTool.ContainsIPv4(clientIp4, ip4Range);

			//This is a little trickier, want recursion aware algorithm
		}

		private static SPFQualifier ExtractQualifier(string spfRecordMechanism, SPFMechanism spfMechanism)
		{
			spfRecordMechanism = spfRecordMechanism.Trim();
			switch (spfMechanism)
			{
				case SPFMechanism.ALL:
					return ExtractQualifier(spfRecordMechanism, "all");
				case SPFMechanism.IP4:
					return ExtractQualifier(spfRecordMechanism, "ip4");
				case SPFMechanism.IP6:
					return ExtractQualifier(spfRecordMechanism, "ip6");
				case SPFMechanism.A:
					return ExtractQualifier(spfRecordMechanism, "a");
				case SPFMechanism.MX:
					return ExtractQualifier(spfRecordMechanism, "mx");
				case SPFMechanism.PTR:
					return ExtractQualifier(spfRecordMechanism, "ptr");
				case SPFMechanism.EXISTS:
					return ExtractQualifier(spfRecordMechanism, "exists");
				case SPFMechanism.INCLUDE:
					return ExtractQualifier(spfRecordMechanism, "include");
			}
			return SPFQualifier.PASS;
		}

		private static SPFQualifier ExtractQualifier(string spfRecordMechanism, string startsWith)
		{
			int index = spfRecordMechanism.IndexOf(startsWith);
			if (index == 0)
			{
				//The default qualifier is "+", i.e. "Pass"
				return SPFQualifier.PASS;
			}
			else if (index == 1)
			{
				//If a mechanism results in a hit, its qualifier value is used
				switch (spfRecordMechanism[0])
				{
					case '+':
						return SPFQualifier.PASS;
					case '-':
						return SPFQualifier.FAIL;
					case '~':
						return SPFQualifier.SOFT_FAIL;
					case '?':
						return SPFQualifier.NEUTRAL;
				}
			}
			throw new ArgumentException("Invalid SPF mechanism qualifier");
		}
	}
}
