import { getParametersValue } from "pvutils";
import BaseClass from "./BaseClass.js";
//**************************************************************************************
export default class Extension extends BaseClass
{
	//**********************************************************************************
	/**
	 * Constructor for Extension class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		super(parameters);
		
		//region Internal properties of the object
		/**
		 * @type {Number}
		 * @description type
		 */
		this.type = getParametersValue(parameters, "type", Extension.constants("type"));
		/**
		 * @type {ArrayBuffer}
		 * @description data
		 */
		this.data = getParametersValue(parameters, "data", Extension.constants("data"));
		//endregion
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
			case "type":
				return 0;
			case "data":
				return (new ArrayBuffer(0));
			default:
				throw new Error(`Invalid constant name for Extension class: ${name}`);
		}
	}
	//**********************************************************************************
	/**
	 * Convert SeqStream data into current class
	 * @param {!SeqStream} stream
	 */
	fromStream(stream)
	{
		this.type = stream.getUint16();
		
		const length = stream.getUint16();
		this.data = (new Uint8Array(stream.getBlock(length))).buffer.slice(0);
	}
	//**********************************************************************************
	/**
	 * Convert current object to SeqStream data
	 * @param {!SeqStream} stream
	 * @returns {boolean} Result of the function
	 */
	toStream(stream)
	{
		stream.appendUint16(this.type);
		stream.appendUint16(this.data.byteLength);
		stream.appendView(new Uint8Array(this.data));
		
		return true;
	}
	//**********************************************************************************
}
//**************************************************************************************
