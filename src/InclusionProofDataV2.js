import { getParametersValue } from "pvutils";
import { utils } from "./utils.js";
import { BaseClass } from "./BaseClass.js";
//**************************************************************************************
export default class InclusionProofDataV2 extends BaseClass
{
	//**********************************************************************************
	/**
	 * Constructor for InclusionProofDataV2 class
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
		this.logID = getParametersValue(parameters, "logID", InclusionProofDataV2.constants("logID"));
		/**
		 * @type {Number}
		 * @description treeSize The size of the tree on which this inclusion proof is based
		 */
		this.treeSize = getParametersValue(parameters, "treeSize", InclusionProofDataV2.constants("treeSize"));
		/**
		 * @type {Number}
		 * @description leafIndex The 0-based index of the log entry corresponding to this inclusion proof
		 */
		this.leafIndex = getParametersValue(parameters, "leafIndex", InclusionProofDataV2.constants("leafIndex"));
		/**
		 * @type {Array.<ArrayBuffer>}
		 * @description inclusionPath
		 */
		this.inclusionPath = getParametersValue(parameters, "inclusionPath", InclusionProofDataV2.constants("inclusionPath"));
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
			case "treeSize":
			case "leafIndex":
				return 0;
			case "inclusionPath":
				return [];
			default:
				throw new Error(`Invalid constant name for InclusionProofDataV2 class: ${name}`);
		}
	}
	//**********************************************************************************
	/**
	 * Convert SeqStream data into current class
	 * @param {!SeqStream} stream
	 */
	fromStream(stream)
	{
		this.logID = utils.getOID(stream, "InclusionProofDataV2");
		this.treeSize = utils.getUint64(stream);
		this.leafIndex = utils.getUint64(stream);
		
		let pathLength = stream.getUint16();
		
		while(pathLength)
		{
			const hashLength = (stream.getBlock(1))[0];
			this.inclusionPath.push((new Uint8Array(stream.getBlock(hashLength))).buffer.slice(0));
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
		utils.appendUint64(this.treeSize, stream);
		utils.appendUint64(this.leafIndex, stream);
		
		stream.appendUint16(this.inclusionPath.length);
		
		for(const inclusion of this.inclusionPath)
		{
			stream.appendChar(inclusion.byteLength);
			stream.appendView(new Uint8Array(inclusion));
		}

		return true;
	}
	//**********************************************************************************
}
//**************************************************************************************
