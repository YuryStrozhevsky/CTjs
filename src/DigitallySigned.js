import * as asn1js from "asn1js";
import { getParametersValue } from "pvutils";
import { getEngine } from "pkijs";
import { BaseClass } from "./BaseClass.js";
//**************************************************************************************
export default class DigitallySigned extends BaseClass
{
	//**********************************************************************************
	/**
	 * Constructor for DigitallySigned class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		super(parameters);
		
		//region Internal properties of the object
		/**
		 * @type {string}
		 * @description hashAlgorithm
		 */
		this.hashAlgorithm = getParametersValue(parameters, "hashAlgorithm", DigitallySigned.constants("hashAlgorithm"));
		/**
		 * @type {string}
		 * @description signatureAlgorithm
		 */
		this.signatureAlgorithm = getParametersValue(parameters, "signatureAlgorithm", DigitallySigned.constants("signatureAlgorithm"));
		/**
		 * @type {Object}
		 * @description signature ASN1js parsed object representing signature
		 */
		this.signature = getParametersValue(parameters, "signature", DigitallySigned.constants("signature"));
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
			case "hashAlgorithm":
				return "none";
			case "signatureAlgorithm":
				return "anonymous";
			case "signature":
				return (new asn1js.Any());
			default:
				throw new Error(`Invalid constant name for DigitallySigned class: ${name}`);
		}
	}
	//**********************************************************************************
	/**
	 * Convert SeqStream data into current class
	 * @param {!SeqStream} stream
	 */
	fromStream(stream)
	{
		//region Hash algorithm
		switch((stream.getBlock(1))[0])
		{
			case 0:
				this.hashAlgorithm = "none";
				break;
			case 1:
				this.hashAlgorithm = "md5";
				break;
			case 2:
				this.hashAlgorithm = "sha1";
				break;
			case 3:
				this.hashAlgorithm = "sha224";
				break;
			case 4:
				this.hashAlgorithm = "sha256";
				break;
			case 5:
				this.hashAlgorithm = "sha384";
				break;
			case 6:
				this.hashAlgorithm = "sha512";
				break;
			default:
				throw new Error("Object's stream was not correct for DigitallySigned");
		}
		//endregion
		
		//region Signature algorithm
		switch((stream.getBlock(1))[0])
		{
			case 0:
				this.signatureAlgorithm = "anonymous";
				break;
			case 1:
				this.signatureAlgorithm = "rsa";
				break;
			case 2:
				this.signatureAlgorithm = "dsa";
				break;
			case 3:
				this.signatureAlgorithm = "ecdsa";
				break;
			default:
				throw new Error("Object's stream was not correct for DigitallySigned");
		}
		//endregion
		
		//region Signature
		const signatureLength = stream.getUint16();
		const signatureData = (new Uint8Array(stream.getBlock(signatureLength))).buffer.slice(0);
		
		const asn1 = asn1js.fromBER(signatureData);
		if(asn1.offset === (-1))
			throw new Error("Object's stream was not correct for DigitallySigned");
		
		this.signature = asn1.result;
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to SeqStream data
	 * @param {!SeqStream} stream
	 * @returns {boolean} Result of the function
	 */
	toStream(stream)
	{
		switch(this.hashAlgorithm.toLowerCase())
		{
			case "none":
				stream.appendChar(0);
				break;
			case "md5":
				stream.appendChar(1);
				break;
			case "sha1":
				stream.appendChar(2);
				break;
			case "sha224":
				stream.appendChar(3);
				break;
			case "sha256":
				stream.appendChar(4);
				break;
			case "sha384":
				stream.appendChar(5);
				break;
			case "sha512":
				stream.appendChar(6);
				break;
			default:
				throw new Error(`Incorrect data for hashAlgorithm: ${this.hashAlgorithm}`);
		}
		
		switch(this.signatureAlgorithm.toLowerCase())
		{
			case "anonymous":
				stream.appendChar(0);
				break;
			case "rsa":
				stream.appendChar(1);
				break;
			case "dsa":
				stream.appendChar(2);
				break;
			case "ecdsa":
				stream.appendChar(3);
				break;
			default:
				throw new Error(`Incorrect data for signatureAlgorithm: ${this.signatureAlgorithm}`);
		}
		
		const sign = this.signature.toBER(false);
		
		stream.appendUint16(sign.byteLength);
		stream.appendView(new Uint8Array(sign));
		
		return true;
	}
	//**********************************************************************************
	/**
	 * Verify existing signature given data block and public key
	 * @param {ArrayBuffer} data The data to be verified against existing signature
	 * @param {PublicKeyInfo} publicKey Public key using for verification
	 * @return {Promise<Boolean>}
	 */
	async verify(data, publicKey)
	{
		//region Perform verification
		return getEngine().subtle.verifyWithPublicKey(
			data,
			{ valueBlock: { valueHex: this.signature.toBER(false) } },
			publicKey,
			{ algorithmId: "" },
			"SHA-256"
		);
		//endregion
	}
	//**********************************************************************************
}
//**************************************************************************************

