import { getParametersValue, utilConcatBuf } from "pvutils";
import { getCrypto } from "pkijs";
import { BaseClass } from "./BaseClass.js";
import TimestampedCertificateEntryDataV2 from "./TimestampedCertificateEntryDataV2.js";
import SignedCertificateTimestampDataV2 from "./SignedCertificateTimestampDataV2.js";
import SignedTreeHeadDataV2 from "./SignedTreeHeadDataV2.js";
import ConsistencyProofDataV2 from "./ConsistencyProofDataV2.js";
import InclusionProofDataV2 from "./InclusionProofDataV2.js";
//**************************************************************************************
export default class TransItem extends BaseClass
{
	//**********************************************************************************
	/**
	 * Constructor for TransItem class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		super(parameters);
		
		//region Internal properties of the object
		/**
		 * @type {Number}
		 * @description type
		 */
		this.type = getParametersValue(parameters, "type", TransItem.constants("type"));
		/**
		 * @type {*}
		 * @description data
		 */
		this.data = getParametersValue(parameters, "data", TransItem.constants("data"));
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
			case "type":
				return (-1);
			case "data":
				return {};
			case "x509_entry_v2":
				return 1;
			case "precert_entry_v2":
				return 2;
			case "x509_sct_v2":
				return 3;
			case "precert_sct_v2":
				return 4;
			case "signed_tree_head_v2":
				return 5;
			case "consistency_proof_v2":
				return 6;
			case "inclusion_proof_v2":
				return 7;
			default:
				throw new Error(`Invalid constant name for TransItem class: ${name}`);
		}
	}
	//**********************************************************************************
	/**
	 * Convert SeqStream data into current class
	 * @param {!SeqStream} stream
	 */
	fromStream(stream)
	{
		this.type = stream.getUint16();
		
		switch(this.type)
		{
			case TransItem.constants("x509_entry_v2"):
			case TransItem.constants("precert_entry_v2"):
				this.data = new TimestampedCertificateEntryDataV2({ stream });
				break;
			case TransItem.constants("x509_sct_v2"):
			case TransItem.constants("precert_sct_v2"):
				this.data = new SignedCertificateTimestampDataV2({ stream });
				break;
			case TransItem.constants("signed_tree_head_v2"):
				this.data = new SignedTreeHeadDataV2({ stream });
				break;
			case TransItem.constants("consistency_proof_v2"):
				this.data = new ConsistencyProofDataV2({ stream });
				break;
			case TransItem.constants("inclusion_proof_v2"):
				this.data = new InclusionProofDataV2({ stream });
				break;
			default:
				throw new Error("Object's stream was not correct for TransItem");
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
		stream.appendUint16(this.type);
		this.data.toStream(stream);
		
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
