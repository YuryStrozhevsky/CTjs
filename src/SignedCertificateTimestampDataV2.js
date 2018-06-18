import { getParametersValue } from "pvutils";
import { utils } from "./utils.js";
import Extension from "./Extension.js";
import BaseClass from "./BaseClass.js";
//**************************************************************************************
export default class SignedCertificateTimestampDataV2 extends BaseClass
{
	//**********************************************************************************
	/**
	 * Constructor for SignedCertificateTimestampDataV2 class
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
		this.logID = getParametersValue(parameters, "logID", SignedCertificateTimestampDataV2.constants("logID"));
		/**
		 * @type {Date}
		 * @description timestamp
		 */
		this.timestamp = getParametersValue(parameters, "timestamp", SignedCertificateTimestampDataV2.constants("timestamp"));
		/**
		 * @type {Array.<Extension>}
		 * @description extensions
		 */
		this.extensions = getParametersValue(parameters, "extensions", SignedCertificateTimestampDataV2.constants("extensions"));
		/**
		 * @type {ArrayBuffer}
		 * @description signature
		 */
		this.signature = getParametersValue(parameters, "signature", SignedCertificateTimestampDataV2.constants("signature"));
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
			case "timestamp":
				return (new Date());
			case "extensions":
				return [];
			case "signature":
				return (new ArrayBuffer(0));
			default:
				throw new Error(`Invalid constant name for SignedCertificateTimestampDataV2 class: ${name}`);
		}
	}
	//**********************************************************************************
	/**
	 * Convert SeqStream data into current class
	 * @param {!SeqStream} stream
	 */
	fromStream(stream)
	{
		this.logID = utils.getOID(stream, "SignedCertificateTimestampDataV2");
		
		this.timestamp = new Date(utils.getUint64(stream));
		
		let extensionsCount = stream.getUint16();
		
		while(extensionsCount)
		{
			this.extensions.push(new Extension({ stream }));
			extensionsCount--;
		}
		
		const signatureLength = stream.getUint16();
		
		this.signature = (new Uint8Array(stream.getBlock(signatureLength))).buffer.slice(0);
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
		utils.appendUint64(this.timestamp.valueOf(), stream);
		
		stream.appendUint16(this.extensions.length);

		if(this.extensions.length)
		{
			for(const extension of this.extensions)
				extension.toStream(stream);
		}

		stream.appendUint16(this.signature.byteLength);
		stream.appendView(new Uint8Array(this.signature));
		
		return true;
	}
	//**********************************************************************************
}
//**************************************************************************************
