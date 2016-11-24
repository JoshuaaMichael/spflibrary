using spflibrary.enums;

namespace spflibrary.interfaces
{
	interface ISPFCheck
	{
		SPFResult PerformCheck(string ipAddress, string domain);
	}
}
