import { getParametersValue, stringToArrayBuffer, fromBase64 } from "pvutils";
import { SeqStream } from "bytestreamjs";
import { utils } from "./utils.js";
import DigitallySigned from "./DigitallySigned.js";
import LogEntryType from "./LogEntryType.js";
import { BaseClass } from "./BaseClass.js";
//**************************************************************************************
export default class SignedCertificateTimestamp extends BaseClass
{
	//**********************************************************************************
	/**
	 * Constructor for SignedCertificateTimestamp class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		super(parameters);
		
		//region Internal properties of the object
		/**
		 * @type {number}
		 * @description version
		 */
		this.version = getParametersValue(parameters, "version", SignedCertificateTimestamp.constants("version"));
		/**
		 * @type {ArrayBuffer}
		 * @description logID
		 */
		this.logID = getParametersValue(parameters, "logID", SignedCertificateTimestamp.constants("logID"));
		/**
		 * @type {Date}
		 * @description timestamp
		 */
		this.timestamp = getParametersValue(parameters, "timestamp", SignedCertificateTimestamp.constants("timestamp"));
		/**
		 * @type {ArrayBuffer}
		 * @description extensions
		 */
		this.extensions = getParametersValue(parameters, "extensions", SignedCertificateTimestamp.constants("extensions"));
		/**
		 * @type {DigitallySigned}
		 * @description signature
		 */
		this.signature = getParametersValue(parameters, "signature", SignedCertificateTimestamp.constants("signature"));
		//endregion
		
		//region If input argument array contains "stream"
		if("stream" in parameters)
			this.fromStream(parameters.stream);
		//endregion
		
		//region If input argument array contains "json" for this object
		if("json" in parameters)
			this.fromJSON(parameters.json);
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
			case "version":
				return 0;
			case "logID":
			case "extensions":
				return new ArrayBuffer(0);
			case "timestamp":
				return new Date(0);
			case "signature":
				return new DigitallySigned();
			default:
				throw new Error(`Invalid constant name for SignedCertificateTimestamp class: ${name}`);
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
		// 	Version sct_version;
		// 	LogID id;
		// 	uint64 timestamp;
		// 	CtExtensions extensions;
		// 	digitally-signed struct {
		// 		Version sct_version;
		// 		SignatureType signature_type = certificate_timestamp;
		// 		uint64 timestamp;
		// 		LogEntryType entry_type;
		// 		select(entry_type) {
		// 			case x509_entry: ASN.1Cert;
		// 			case precert_entry: PreCert;
		// 		} signed_entry;
		// 		CtExtensions extensions;
		// 	};
		// } SignedCertificateTimestamp;

		const blockLength = stream.getUint16();
		
		this.version = (stream.getBlock(1))[0];
		
		this.logID = (new Uint8Array(stream.getBlock(32))).buffer.slice(0);
		this.timestamp = new Date(utils.getUint64(stream));
		
		//region Extensions
		const extensionsLength = stream.getUint16();
		this.extensions = (new Uint8Array(stream.getBlock(extensionsLength))).buffer.slice(0);
		//endregion
		
		this.signature = new DigitallySigned({ stream });
		
		if(blockLength !== (47 + extensionsLength + this.signature.signature.valueBeforeDecode.byteLength))
			throw new Error("Object's stream was not correct for SignedCertificateTimestamp");
	}
	//**********************************************************************************
	/**
	 * Convert JSON value into current object
	 * @param {Object} json
	 * @param {String} json.sct_version
	 * @param {String} json.id
	 * @param {String} json.timestamp
	 * @param {String} json.extensions
	 * @param {String} json.signature
	 */
	fromJSON(json)
	{
		this.version = json.sct_version;
		this.logID = stringToArrayBuffer(fromBase64(json.id));
		this.timestamp = new Date(json.timestamp);
		this.extensions = stringToArrayBuffer(fromBase64(json.extensions));
		this.signature = new DigitallySigned({
			stream: new SeqStream({
				buffer: stringToArrayBuffer(fromBase64(json.signature))
			})
		});
	}
	//**********************************************************************************
	/**
	 * Convert current object to SeqStream data
	 * @param {!SeqStream} stream
	 * @returns {boolean} Result of the function
	 */
	toStream(stream)
	{
		stream.appendUint16(47 + this.extensions.byteLength + this.signature.valueBeforeDecode.byteLength);
		stream.appendChar(this.version);
		stream.appendView(new Uint8Array(this.logID));
		
		utils.appendUint64(this.timestamp.valueOf(), stream);
		
		stream.appendUint16(this.extensions.byteLength);
		
		if(this.extensions.byteLength)
			stream.appendView(new Uint8Array(this.extensions));
		
		this.signature.toStream(stream);
		
		return true;
	}
	//**********************************************************************************
	/**
	 * Verify SignedCertificateTimestamp for specific input data
	 * @param {ArrayBuffer} data Data to verify signature against. Could be encoded Certificate or encoded PreCert
	 * @param {PublicKeyInfo} publicKey The PublicKeyInfo class from PKI.js having public key for the CT log
	 * @param {Number} [dataType=x509_entry] Type = 0 (data is encoded Certificate), type = 1 (data is encoded PreCert)
	 * @return {Promise<Boolean>}
	 */
	async verify(data, publicKey, dataType = LogEntryType.constants("x509_entry"))
	{
		const stream = new SeqStream();
		
		//region Initialize signed data block
		stream.appendChar(0x00); // sct_version
		stream.appendChar(0x00); // signature_type = certificate_timestamp
		
		utils.appendUint64(this.timestamp.valueOf(), stream);
		
		stream.appendUint16(dataType);
		
		if(dataType === LogEntryType.constants("x509_entry"))
			stream.appendUint24(data.byteLength);
		
		stream.appendView(new Uint8Array(data));
		
		stream.appendUint16(this.extensions.byteLength);
		
		if(this.extensions.byteLength !== 0)
			stream.appendView(new Uint8Array(this.extensions));
		//endregion
		
		return this.signature.verify(stream.buffer, publicKey);
	}
	//**********************************************************************************
}
//**************************************************************************************
