//**************************************************************************************
export default class LogEntryType
{
	//**********************************************************************************
	constructor()
	{
		throw new Error("Only calls to static functions allowed for namespace 'LogEntryType'");
	}
	//**********************************************************************************
	/**
	 * Return value for a constant by name
	 * @param {string} name String name for a constant
	 */
	static constants(name)
	{
		switch(name)
		{
			case "x509_entry":
				return 0;
			case "precert_entry":
				return 1;
			default:
				throw new Error(`Invalid constant name for LogEntryType class: ${name}`);
		}
	}
	//**********************************************************************************
}
//**************************************************************************************
