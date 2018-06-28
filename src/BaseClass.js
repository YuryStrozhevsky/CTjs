import { SeqStream } from "bytestreamjs";
import { getEngine } from "pkijs";
//**************************************************************************************
export class BaseClass
{
	//**********************************************************************************
	constructor()
	{
	}
	//**********************************************************************************
	/**
	 * Convert current object to SeqStream data
	 * @param {!SeqStream} stream
	 * @returns {boolean} Result of the function
	 */
	toStream(stream)
	{
		return true;
	}
	//**********************************************************************************
	/**
	 * Converts current class into SeqStream and then return ArrayBuffer from the stream
	 * @return {ArrayBuffer}
	 */
	get buffer()
	{
		const stream = new SeqStream();
		
		this.toStream(stream);
		
		return stream.buffer;
	}
	//**********************************************************************************
}
//**************************************************************************************
export class BaseClassSigned extends BaseClass
{
	//**********************************************************************************
	constructor()
	{
		super();
		
		this.signature = {};
	}
	//**********************************************************************************
	/**
	 * Verify existing signature given data block and public key
	 * @param {ArrayBuffer} data The data to be verified against existing signature
	 * @param {PublicKeyInfo} publicKey Public key using for verification
	 * @param {String} [hashName=SHA-256] Name of hashing function, default SHA-256
	 * @return {Promise<Boolean>}
	 */
	async verify(data, publicKey, hashName = "SHA-256")
	{
		//region Perform verification
		return getEngine().subtle.verifyWithPublicKey(
			data,
			{ valueBlock: { valueHex: this.signature.toBER(false) } },
			publicKey,
			{ algorithmId: "" },
			hashName
		);
		//endregion
	}
	//**********************************************************************************
}
//**************************************************************************************
