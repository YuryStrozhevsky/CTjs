import { SeqStream } from "bytestreamjs";
//**************************************************************************************
export default class BaseClass
{
	//**********************************************************************************
	constructor()
	{
	}
	//**********************************************************************************
	/**
	 * Convert current object to SeqStream data
	 * @param {!SeqStream} stream
	 * @returns {boolean} Result of the function
	 */
	toStream(stream)
	{
		return true;
	}
	//**********************************************************************************
	/**
	 * Converts current class into SeqStream and then return ArrayBuffer from the stream
	 * @return {ArrayBuffer}
	 */
	get buffer()
	{
		const stream = new SeqStream();
		
		this.toStream(stream);
		
		return stream.buffer;
	}
	//**********************************************************************************
}
//**************************************************************************************
