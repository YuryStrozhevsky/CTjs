import { getParametersValue } from "pvutils";
import { utils } from "./utils.js";
import BaseClass from "./BaseClass.js";
//**************************************************************************************
export default class ConsistencyProofDataV2 extends BaseClass
{
	//**********************************************************************************
	/**
	 * Constructor for ConsistencyProofDataV2 class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		super(parameters);
		
		//region Internal properties of the object
		/**
		 * @type {String}
		 * @description logID OID representing used Certificate Transparency Log
		 */
		this.logID = getParametersValue(parameters, "logID", ConsistencyProofDataV2.constants("logID"));
		/**
		 * @type {Number}
		 * @description treeSize1 The size of the older tree
		 */
		this.treeSize1 = getParametersValue(parameters, "treeSize1", ConsistencyProofDataV2.constants("treeSize1"));
		/**
		 * @type {Number}
		 * @description treeSize2 The size of the newer tree
		 */
		this.treeSize2 = getParametersValue(parameters, "treeSize2", ConsistencyProofDataV2.constants("treeSize2"));
		/**
		 * @type {Array.<ArrayBuffer>}
		 * @description consistencyPath
		 */
		this.consistencyPath = getParametersValue(parameters, "consistencyPath", ConsistencyProofDataV2.constants("consistencyPath"));
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
			case "logID":
				return "";
			case "treeSize1":
			case "treeSize2":
				return 0;
			case "consistencyPath":
				return [];
			default:
				throw new Error(`Invalid constant name for ConsistencyProofDataV2 class: ${name}`);
		}
	}
	//**********************************************************************************
	/**
	 * Convert SeqStream data into current class
	 * @param {!SeqStream} stream
	 */
	fromStream(stream)
	{
		this.logID = utils.getOID(stream, "ConsistencyProofDataV2");
		
		this.treeSize1 = utils.getUint64(stream);
		this.treeSize2 = utils.getUint64(stream);
		
		let pathLength = stream.getUint16();
		
		while(pathLength)
		{
			const hashLength = (stream.getBlock(1))[0];
			this.consistencyPath.push((new Uint8Array(stream.getBlock(hashLength))).buffer.slice(0));
			pathLength--;
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
		utils.appendOID(this.logID, stream);
		
		utils.appendUint64(this.treeSize1, stream);
		utils.appendUint64(this.treeSize2, stream);

		stream.appendUint16(this.consistencyPath.length);
		
		for(const consistency of this.consistencyPath)
		{
			stream.appendChar(consistency.byteLength);
			stream.appendView(new Uint8Array(consistency));
		}
		
		return true;
	}
	//**********************************************************************************
}
//**************************************************************************************
