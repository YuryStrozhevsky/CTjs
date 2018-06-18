import { getParametersValue, fromBase64, stringToArrayBuffer } from "pvutils";
import { SeqStream } from "bytestreamjs";
import DigitallySigned from "./DigitallySigned.js";
import { utils } from "./utils.js";
//**************************************************************************************
export default class SignedTreeHead
{
	//**********************************************************************************
	/**
	 * Constructor for SignedTreeHead class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {Number}
		 * @description treeSize
		 */
		this.treeSize = getParametersValue(parameters, "treeSize", SignedTreeHead.constants("treeSize"));
		/**
		 * @type {Date}
		 * @description timestamp
		 */
		this.timestamp = getParametersValue(parameters, "timestamp", SignedTreeHead.constants("timestamp"));
		/**
		 * @type {ArrayBuffer}
		 * @description rootHash
		 */
		this.rootHash = getParametersValue(parameters, "rootHash", SignedTreeHead.constants("rootHash"));
		/**
		 * @type {DigitallySigned}
		 * @description treeHeadSignature
		 */
		this.treeHeadSignature = getParametersValue(parameters, "treeHeadSignature", SignedTreeHead.constants("treeHeadSignature"));
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
			case "treeSize":
				return 0;
			case "timestamp":
				return (new Date());
			case "rootHash":
				return (new ArrayBuffer(0));
			case "treeHeadSignature":
				return (new DigitallySigned());
			default:
				throw new Error(`Invalid constant name for SignedTreeHead class: ${name}`);
		}
	}
	//**********************************************************************************
	/**
	 * Convert JSON value into current object
	 * @param {Object} json
	 * @param {String} json.tree_size
	 * @param {String} json.timestamp
	 * @param {String} json.sha256_root_hash
	 * @param {String} json.tree_head_signature
	 */
	fromJSON(json)
	{
		this.treeSize = json.tree_size;
		this.timestamp = new Date(json.timestamp);
		this.rootHash = stringToArrayBuffer(fromBase64(json.sha256_root_hash));
		
		const stream = new SeqStream({
			buffer: stringToArrayBuffer(fromBase64(json.tree_head_signature))
		});
		
		this.treeHeadSignature = new DigitallySigned({ stream });
	}
	//**********************************************************************************
	/**
	 * Verify Signed Tree Head using given public key
	 * @param {PublicKeyInfo} publicKey Public key using for verification
	 * @return {Promise<Boolean>}
	 */
	async verify(publicKey)
	{
		// digitally-signed struct {
		// 	Version version;
		// 	SignatureType signature_type = tree_hash;
		// 	uint64 timestamp;
		// 	uint64 tree_size;
		// 	opaque sha256_root_hash[32];
		// } TreeHeadSignature;

		const stream = new SeqStream();
		
		stream.appendChar(0); // version
		stream.appendChar(1); // signature_type = tree_hash;
		
		utils.appendUint64(this.timestamp.valueOf(), stream); // timestamp
		utils.appendUint64(this.treeSize, stream); // tree_size
		
		stream.appendView(new Uint8Array(this.rootHash)); // sha256_root_hash
		
		return this.treeHeadSignature.verify(stream.buffer, publicKey);
	}
	//**********************************************************************************
}
//**************************************************************************************
