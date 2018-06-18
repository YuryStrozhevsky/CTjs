import * as asn1js from "asn1js";
import { getParametersValue } from "pvutils";
import { utils } from "./utils.js";
import Extension from "./Extension.js";
import BaseClass from "./BaseClass.js";
//**************************************************************************************
export default class TimestampedCertificateEntryDataV2 extends BaseClass
{
	//**********************************************************************************
	/**
	 * Constructor for TimestampedCertificateEntryDataV2 class
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
		this.timestamp = getParametersValue(parameters, "timestamp", TimestampedCertificateEntryDataV2.constants("timestamp"));
		/**
		 * @type {ArrayBuffer}
		 * @description issuerKeyHash
		 */
		this.issuerKeyHash = getParametersValue(parameters, "issuerKeyHash", TimestampedCertificateEntryDataV2.constants("issuerKeyHash"));
		/**
		 * @type {ArrayBuffer}
		 * @description rootHash
		 */
		this.rootHash = getParametersValue(parameters, "rootHash", TimestampedCertificateEntryDataV2.constants("rootHash"));
		/**
		 * @type {Object}
		 * @description tbsCertificate
		 */
		this.tbsCertificate = getParametersValue(parameters, "tbsCertificate", TimestampedCertificateEntryDataV2.constants("tbsCertificate"));
		/**
		 * @type {Array.<Extension>}
		 * @description extensions
		 */
		this.extensions = getParametersValue(parameters, "extensions", TimestampedCertificateEntryDataV2.constants("extensions"));
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
			case "issuerKeyHash":
				return (new ArrayBuffer(0));
			case "tbsCertificate":
				return (new asn1js.Any());
			case "extensions":
				return [];
			default:
				throw new Error(`Invalid constant name for TimestampedCertificateEntryDataV2 class: ${name}`);
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
		
		const hashLength = (stream.getBlock(1))[0];
		this.issuerKeyHash = (new Uint8Array(stream.getBlock(hashLength))).buffer.slice(0);
		
		const tbsLength = stream.getUint24();
		
		const asn1 = asn1js.fromBER((new Uint8Array(stream.getBlock(tbsLength))).buffer.slice(0));
		if(asn1.offset === (-1))
			throw new Error("Object's stream was not correct for TimestampedCertificateEntryDataV2");
		
		this.tbsCertificate = asn1.result;
		
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

		stream.appendChar(this.issuerKeyHash.byteLength);
		stream.appendView(new Uint8Array(this.issuerKeyHash));
		
		const tbs = this.tbsCertificate.toBER(false);
		
		stream.appendUint24(tbs.byteLength);
		stream.appendView(new Uint8Array(tbs));
		
		stream.appendUint16(this.extensions.length);
		
		for(const extension of this.extensions)
			extension.toStream(stream);
		
		return true;
	}
	//**********************************************************************************
}
//**************************************************************************************
