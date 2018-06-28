import { getParametersValue, utilConcatBuf } from "pvutils";
import { getCrypto } from "pkijs";
import TimestampedEntry from "./TimestampedEntry.js";
import { BaseClass } from "./BaseClass.js";
//**************************************************************************************
export default class MerkleTreeLeaf extends BaseClass
{
	//**********************************************************************************
	/**
	 * Constructor for MerkleTreeLeaf class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		super(parameters);
		
		//region Internal properties of the object
		/**
		 * @type {Number}
		 * @description version
		 */
		this.version = getParametersValue(parameters, "version", MerkleTreeLeaf.constants("version"));
		/**
		 * @type {Number}
		 * @description leafType
		 */
		this.leafType = getParametersValue(parameters, "leafType", MerkleTreeLeaf.constants("leafType"));
		/**
		 * @type {TimestampedEntry}
		 * @description entry
		 */
		this.entry = getParametersValue(parameters, "entry", MerkleTreeLeaf.constants("entry"));
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
			case "version":
				return 0;
			case "leafType":
				return 0;
			case "entry":
				return (new TimestampedEntry());
			default:
				throw new Error(`Invalid constant name for MerkleTreeLeaf class: ${name}`);
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
		// 	Version version;
		// 	MerkleLeafType leaf_type;
		// 	select (leaf_type) {
		// 		case timestamped_entry: TimestampedEntry;
		// 	}
		// } MerkleTreeLeaf;

		this.version = (stream.getBlock(1))[0];
		this.leafType = (stream.getBlock(1))[0];
		this.entry = new TimestampedEntry({ stream });
	}
	//**********************************************************************************
	/**
	 * Convert current object to SeqStream data
	 * @param {!SeqStream} stream
	 * @returns {boolean} Result of the function
	 */
	toStream(stream)
	{
		stream.appendChar(this.version);
		stream.appendChar(this.leafType);
		this.entry.toStream(stream);
		
		return true;
	}
	//**********************************************************************************
	/**
	 * Get hash value for the MerkleTreeLeaf
	 * @param {String} [hashName=SHA-256] Name of hashing function, default SHA-256
	 * @return {Promise<ArrayBuffer>}
	 */
	async hash(hashName = "SHA-256")
	{
		//region Get a "crypto" extension
		const crypto = getCrypto();
		if(typeof crypto === "undefined")
			throw new Error("Unable to create WebCrypto object");
		//endregion
		
		const prefixedBuffer = utilConcatBuf((new Uint8Array([0x00])).buffer, this.buffer);
		
		return await crypto.digest({ name: hashName }, prefixedBuffer);
	}
	//**********************************************************************************
}
//**************************************************************************************
