import * as asn1js from "asn1js";
import { getParametersValue } from "pvutils";
import { getCrypto, Certificate, AlgorithmIdentifier } from "pkijs";
import BaseClass from "./BaseClass.js";
//**************************************************************************************
export default class PreCert extends BaseClass
{
	//**********************************************************************************
	/**
	 * Constructor for PreCert class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		super(parameters);
		
		//region Internal properties of the object
		/**
		 * @type {ArrayBuffer}
		 * @description issuerKeyHash
		 */
		this.issuerKeyHash = getParametersValue(parameters, "issuerKeyHash", PreCert.constants("issuerKeyHash"));
		/**
		 * @type {Object}
		 * @description tbsCertificate ASN1js parsed object representing TBS of certificate
		 */
		this.tbsCertificate = getParametersValue(parameters, "tbsCertificate", PreCert.constants("tbsCertificate"));
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
			case "issuerKeyHash":
				return (new ArrayBuffer(0));
			case "tbsCertificate":
				return (new asn1js.Any());
			default:
				throw new Error(`Invalid constant name for PreCert class: ${name}`);
		}
	}
	//**********************************************************************************
	/**
	 * Convert SeqStream data into current class
	 * @param {!SeqStream} stream
	 */
	fromStream(stream)
	{
		this.issuerKeyHash = (new Uint8Array(stream.getBlock(32))).buffer.slice(0);
		
		const tbsLength = stream.getUint24();
		
		const asn1 = asn1js.fromBER((new Uint8Array(stream.getBlock(tbsLength))).buffer.slice(0));
		if(asn1.offset === (-1))
			throw new Error("Object's stream was not correct for PreCert");
		
		this.tbsCertificate = asn1.result;
	}
	//**********************************************************************************
	/**
	 * Convert current object to SeqStream data
	 * @param {!SeqStream} stream
	 * @returns {boolean} Result of the function
	 */
	toStream(stream)
	{
		stream.appendView(new Uint8Array(this.issuerKeyHash));
		
		const buffer = this.tbsCertificate.toBER(false);
		
		stream.appendUint24(buffer.byteLength);
		stream.appendView(new Uint8Array(buffer));
		
		return true;
	}
	//**********************************************************************************
	/**
	 * Convert end-entity certificate + issuer certificate into PreCert class
	 * @param {!Object} parameters
	 * @param {Certificate} parameters.certificate End-entity certificate
	 * @param {Certificate} parameters.issuer Issuer's certificate for the end-entity certificate
	 * @return {Promise<PreCert>}
	 */
	static async fromCertificateAndIssuer(parameters)
	{
		//region Initial variables
		const result = new PreCert();
		//endregion
		
		//region Get a "crypto" extension
		const crypto = getCrypto();
		if(typeof crypto === "undefined")
			return Promise.reject("Unable to create WebCrypto object");
		//endregion
		
		//region Check input parameters
		if(("certificate" in parameters) === false)
			throw new Error("Missing mandatory parameter: certificate");
		
		if(("issuer" in parameters) === false)
			throw new Error("Missing mandatory parameter: issuer");
		//endregion
		
		//region Remove certificate extension
		for(let i = 0; i < parameters.certificate.extensions.length; i++)
		{
			switch(parameters.certificate.extensions[i].extnID)
			{
				case "1.3.6.1.4.1.11129.2.4.2":
				case "1.3.6.1.4.1.11129.2.4.3":
					parameters.certificate.extensions.splice(i, 1);
					break;
				default:
			}
		}
		//endregion
		
		//region Prepare modifier TBS value
		result.tbsCertificate = parameters.certificate.encodeTBS();
		//endregion
		
		//region Initialize "issuer_key_hash" value
		result.issuerKeyHash = await crypto.digest({ name: "SHA-256" }, new Uint8Array(parameters.issuer.subjectPublicKeyInfo.toSchema().toBER(false)));
		//endregion
		
		return result;
	}
	//**********************************************************************************
	/**
	 * Fictive X.509 Certificate made from existing PreCert.
	 *
	 * Could be interesting to get such certificate, encode it as a DER and then open the
	 * data in UI like Windows - this would provide ability for easily checking PreCert values
	 */
	get certificate()
	{
		return (new Certificate({
			schema: new asn1js.Sequence({
				value: [
					this.tbsCertificate,
					(new AlgorithmIdentifier({
						algorithmId: "1.2.840.113549.1.1.11",
						algorithmParams: new asn1js.Null()
					})).toSchema(),
					new asn1js.BitString({
						valueHex: new ArrayBuffer(2),
						unusedBits: 0
					})
				]
			})
		}));
	}
	//**********************************************************************************
}
//**************************************************************************************
