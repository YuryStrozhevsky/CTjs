import * as asn1js from "asn1js";
import { getParametersValue, utilFromBase, utilToBase } from "pvutils";
import { Certificate } from "pkijs";
import PreCert from "./PreCert.js";
import LogEntryType from "./LogEntryType.js";
import BaseClass from "./BaseClass.js";
//**************************************************************************************
export default class TimestampedEntry extends BaseClass
{
	//**********************************************************************************
	/**
	 * Constructor for TimestampedEntry class
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
		this.timestamp = getParametersValue(parameters, "timestamp", TimestampedEntry.constants("timestamp"));
		/**
		 * @type {Number}
		 * @description entryType
		 */
		this.entryType = getParametersValue(parameters, "entryType", TimestampedEntry.constants("entryType"));
		/**
		 * @type {Certificate|PreCert}
		 * @description signedEntry
		 */
		this.signedEntry = getParametersValue(parameters, "signedEntry", TimestampedEntry.constants("signedEntry"));
		/**
		 * @type {ArrayBuffer}
		 * @description extensions
		 */
		this.extensions = getParametersValue(parameters, "extensions", TimestampedEntry.constants("extensions"));
		//endregion
		
		//region If input argument array contains "stream" for this object
		if("stream" in parameters)
			this.fromStream(parameters.stream);
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
			case "entryType":
				return LogEntryType.constants("x509_entry");
			case "signedEntry":
				return {};
			case "extensions":
				return (new ArrayBuffer(0));
			default:
				throw new Error(`Invalid constant name for TimestampedEntry class: ${name}`);
		}
	}
	//**********************************************************************************
	/**
	 * Convert SeqStream data into current class
	 * @param {!SeqStream} stream
	 */
	fromStream(stream)
	{
		// struct {
		// 	uint64 timestamp;
		// 	LogEntryType entry_type;
		// 	select(entry_type) {
		// 		case x509_entry: ASN.1Cert;
		// 		case precert_entry: PreCert;
		// 	} signed_entry;
		// 	CtExtensions extensions;
		// } TimestampedEntry;

		this.timestamp = new Date(utilFromBase(new Uint8Array(stream.getBlock(8)), 8));
		this.entryType = stream.getUint16();
		
		switch(this.entryType)
		{
			case LogEntryType.constants("x509_entry"):
				{
					const certificateLength = stream.getUint24();
					
					const asn1 = asn1js.fromBER((new Uint8Array(stream.getBlock(certificateLength))).buffer.slice(0));
					if(asn1.offset === (-1))
						throw new Error("Object's stream was not correct for TimestampedEntry");
					
					this.signedEntry = new Certificate({ schema: asn1.result });
				}
				break;
			case LogEntryType.constants("precert_entry"):
				this.signedEntry = new PreCert({ stream });
				break;
			default:
				throw new Error("Object's stream was not correct for TimestampedEntry");
		}
		
		const extensionsLength = stream.getUint16();
		
		if(extensionsLength)
			this.extensions = (new Uint8Array(stream.getBlock(extensionsLength))).buffer.slice(0);
	}
	//**********************************************************************************
	/**
	 * Convert current object to SeqStream data
	 * @param {!SeqStream} stream
	 * @returns {boolean} Result of the function
	 */
	toStream(stream)
	{
		const timeBuffer = new ArrayBuffer(8);
		const timeView = new Uint8Array(timeBuffer);
		
		const baseArray = utilToBase(this.timestamp.valueOf(), 8);
		timeView.set(new Uint8Array(baseArray), 8 - baseArray.byteLength);
		
		stream.appendView(timeView);
		stream.appendUint16(this.entryType);
		
		switch(this.entryType)
		{
			case LogEntryType.constants("x509_entry"):
				{
					const buffer = this.signedEntry.toSchema().toBER(false);
					
					stream.appendUint24(buffer.byteLength);
					stream.appendView(new Uint8Array(buffer));
				}
				break;
			case LogEntryType.constants("precert_entry"):
				this.signedEntry.toStream(stream);
				break;
			default:
				throw new Error("Incorrect entryType value for TimestampedEntry");
		}
		
		stream.appendUint16(this.extensions.byteLength);
		
		if(this.extensions.byteLength !== 0)
			stream.appendView(new Uint8Array(this.extensions));
		
		return true;
	}
	//**********************************************************************************
}
//**************************************************************************************
