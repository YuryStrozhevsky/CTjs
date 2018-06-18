import { getParametersValue } from "pvutils";
import { utils } from "./utils.js";
import BaseClass from "./BaseClass.js";
import Extension from "./Extension.js";
//**************************************************************************************
export default class TreeHeadDataV2 extends BaseClass
{
	//**********************************************************************************
	/**
	 * Constructor for TreeHeadDataV2 class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		super(parameters);
		
		//region Internal properties of the object
		/**
		 * @type {Date}
		 * @description timestamp
		 */
		this.timestamp = getParametersValue(parameters, "timestamp", TreeHeadDataV2.constants("timestamp"));
		/**
		 * @type {Number}
		 * @description treeSize
		 */
		this.treeSize = getParametersValue(parameters, "treeSize", TreeHeadDataV2.constants("treeSize"));
		/**
		 * @type {ArrayBuffer}
		 * @description rootHash
		 */
		this.rootHash = getParametersValue(parameters, "rootHash", TreeHeadDataV2.constants("rootHash"));
		/**
		 * @type {Array.<Extension>}
		 * @description extensions
		 */
		this.extensions = getParametersValue(parameters, "extensions", TreeHeadDataV2.constants("extensions"));
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
			case "timestamp":
				return (new Date());
			case "treeSize":
				return 0;
			case "rootHash":
				return (new ArrayBuffer(0));
			case "extensions":
				return [];
			default:
				throw new Error(`Invalid constant name for TreeHeadDataV2 class: ${name}`);
		}
	}
	//**********************************************************************************
	/**
	 * Convert SeqStream data into current class
	 * @param {!SeqStream} stream
	 */
	fromStream(stream)
	{
		this.timestamp = new Date(utils.getUint64(stream));
		this.treeSize = utils.getUint64(stream);
		
		const hashLength = (stream.getBlock(1))[0];
		this.rootHash = (new Uint8Array(stream.getBlock(hashLength))).buffer.slice(0);
		
		let extensionsCount = stream.getUint16();
		
		while(extensionsCount)
		{
			this.extensions.push(new Extension({ stream }));
			extensionsCount--;
		}
	}
	//**********************************************************************************
	/**
	 * Convert current object to SeqStream data
	 * @param {!SeqStream} stream
	 * @returns {boolean} Result of the function
	 */
	toStream(stream)
	{
		utils.appendUint64(this.timestamp.valueOf(), stream);
		utils.appendUint64(this.treeSize, stream);
		
		stream.appendChar(this.rootHash.byteLength);
		stream.appendView(new Uint8Array(this.rootHash));
		
		stream.appendUint16(this.extensions.length);
		
		if(this.extensions.length)
		{
			for(const extension of this.extensions)
				extension.toStream(stream);
		}

		return true;
	}
	//**********************************************************************************
}
//**************************************************************************************
