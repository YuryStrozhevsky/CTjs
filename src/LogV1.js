/* eslint-disable no-useless-escape */
import * as asn1js from "asn1js";
import { getParametersValue, fromBase64, stringToArrayBuffer, toBase64, arrayBufferToString } from "pvutils";
import { SeqStream } from "bytestreamjs";
import { Certificate, PublicKeyInfo } from "pkijs";
import SignedTreeHead from "./SignedTreeHead.js";
import MerkleTreeLeaf from "./MerkleTreeLeaf.js";
import SignedCertificateTimestamp from "./SignedCertificateTimestamp.js";
import DigitallySigned from "./DigitallySigned.js";
import LogEntryType from "./LogEntryType.js";
//**************************************************************************************
function handleResult(api)
{
	return async result =>
	{
		if(result.ok)
			return result.json();
		
		let errorMessage = result.statusText;
		
		try
		{
			const errorJSON = await result.json();
			if("error_message" in errorJSON)
				errorMessage = errorJSON.error_message;
		}
		catch(ex){}
		
		throw new Error(`ERROR while fetching ${api}: ${errorMessage}`);
	};
}
//**************************************************************************************
function handleError(api)
{
	return error =>
	{
		if("stack" in error)
			throw new Error(`API '${api}' error: ${error.stack}`);
		
		throw new Error(`API '${api}' error: ${error}`);
	};
}
//**************************************************************************************
export default class LogV1
{
	//**********************************************************************************
	/**
	 * Constructor for Log class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {Function}
		 * @description fetch
		 */
		this.fetch = getParametersValue(parameters, "fetch", LogV1.constants("fetch"));
		/**
		 * @type {Function}
		 * @description encode
		 */
		this.encode = getParametersValue(parameters, "encode", LogV1.constants("encode"));
		
		if("log_id" in parameters)
		{
			/**
			 * @type {String}
			 * @description logID
			 */
			this.logID = stringToArrayBuffer(fromBase64(parameters.log_id));
		}

		if("description" in parameters)
			/**
			 * @type {String}
			 * @description description
			 */
			this.description = getParametersValue(parameters, "description", LogV1.constants("description"));

		if("key" in parameters)
		{
			const asn1 = asn1js.fromBER(stringToArrayBuffer(fromBase64(parameters.key)));
			if(asn1.offset !== (-1))
			{
				/**
				 * @type {PublicKeyInfo}
				 * @description key
				 */
				this.key = new PublicKeyInfo({ schema: asn1.result });
			}
		}
		
		/**
		 * @type {String}
		 * @description url
		 */
		this.url = getParametersValue(parameters, "url", LogV1.constants("url"));
		
		if("maximum_merge_delay" in parameters)
		{
			/**
			 * @type {Number}
			 * @description maximumMergeDelay
			 */
			this.maximumMergeDelay = getParametersValue(parameters, "maximum_merge_delay", LogV1.constants("maximumMergeDelay"));
		}
		
		if("final_sth" in parameters)
		{
			this.finalSTH = {
				treeSize: parameters.final_sth.tree_size,
				timestamp: new Date(parameters.final_sth.timestamp),
				rootHash: stringToArrayBuffer(fromBase64(parameters.final_sth.sha256_root_hash)),
				signature: new DigitallySigned({
					stream: new SeqStream({
						buffer: stringToArrayBuffer(fromBase64(parameters.final_sth.tree_head_signature))
					})
				})
			};
		}
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
			case "fetch":
				return async () => { return Promise.reject("Uninitialized fetch function for LogV1 class"); };
			case "encode":
				return () => { throw new Error("Uninitialized encode function for LogV1 class"); };
			case "description":
			case "url":
				return "";
			case "key":
				return (new PublicKeyInfo());
			case "maximumMergeDelay":
				return 0;
			default:
				throw new Error(`Invalid constant name for LogV1 class: ${name}`);
		}
	}
	//**********************************************************************************
	set url(value)
	{
		if(value === "")
			return;
		
		const match = value.match(/(?:http[s]?:\/\/)?([^?\/s]+.*)/);
		if(match === null)
			throw new Error("Base URL for LogV1 class must be set to a correct value");
		
		this._url = `https://${match[1].replace(/\/*$/g, "")}/ct/v1`;
	}
	//**********************************************************************************\
	get url()
	{
		return this._url;
	}
	//**********************************************************************************
	/**
	 * Implement call to "add-chain" Certificate Transparency Log API
	 * @param {Array.<Certificate>} chain Array of certificates. The first element is the end-entity certificate
	 * @return {Promise<SignedCertificateTimestamp>}
	 */
	async add_chain(chain)
	{
		const api = "add-chain";
		
		/**
		 * @type {Object}
		 * @property {Number} sct_version The version of the SignedCertificateTimestamp structure, in decimal
		 * @property {String} id The log ID, base64 encoded
		 * @property {Number} timestamp The SCT timestamp, in decimal
		 * @property {String} extensions An opaque type for future expansion
		 * @property {String} signature The SCT signature, base64 encoded
		 */
		const json = await this.fetch(
			`${this.url}/${api}`,
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					chain: Array.from(chain, element => toBase64(arrayBufferToString(element.toSchema().toBER(false))))
				})
			})
			.then(handleResult(api), handleError(api));
		
		return (new SignedCertificateTimestamp({ json }));
	}
	//**********************************************************************************
	/**
	 * Implement call to "add-pre-chain" Certificate Transparency Log API
	 * @param {Array.<Certificate>} chain Array of certificates. The first element is the pre-certificate for end-entity
	 * @return {Promise<SignedCertificateTimestamp>}
	 */
	async add_pre_chain(chain)
	{
		const api = "add-pre-chain";
		
		/**
		 * @type {Object}
		 * @property {Number} sct_version The version of the SignedCertificateTimestamp structure, in decimal
		 * @property {String} id The log ID, base64 encoded
		 * @property {Number} timestamp The SCT timestamp, in decimal
		 * @property {String} extensions An opaque type for future expansion
		 * @property {String} signature The SCT signature, base64 encoded
		 */
		const json = await this.fetch(
			`${this.url}/${api}`,
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					chain: Array.from(chain, element => toBase64(arrayBufferToString(element.toSchema().toBER(false))))
				})
			})
			.then(handleResult(api), handleError(api));
		
		return (new SignedCertificateTimestamp({ json }));
	}
	//**********************************************************************************
	/**
	 * Implement call to "get-sth" Certificate Transparency Log API
	 * @return {Promise<SignedTreeHead>} Latest Signed Tree Head
	 */
	async get_sth()
	{
		const api = "get-sth";
		
		const json = await this.fetch(`${this.url}/${api}`)
			.then(handleResult(api), handleError(api));
		
		return (new SignedTreeHead({ json }));
	}
	//**********************************************************************************
	/**
	 * Implement call to "get-sth-consistency" Certificate Transparency Log API
	 * @param {Number} first The tree_size of the first tree, in decimal
	 * @param {Number} second The tree_size of the second tree, in decimal
	 * @return {Promise<Array.<ArrayBuffer>>} An array of Merkle Tree nodes
	 */
	async get_sth_consistency(first, second)
	{
		const api = "get-sth-consistency";
		
		/**
		 * @type {Object}
		 * @property {Array} consistency An array of Merkle Tree nodes, base64 encoded
		 */
		const json = await this.fetch(`${this.url}/${api}?first=${first}&second=${second}`)
			.then(handleResult(api), handleError(api));
		
		return Array.from(json.consistency, element => stringToArrayBuffer(fromBase64(element)));
	}
	//**********************************************************************************
	/**
	 * Implement call to "get-proof-by-hash" Certificate Transparency Log API
	 * @param {MerkleTreeLeaf|ArrayBuffer} hash ArrayBuffer with hash or a MerkleTreeLeaf value making a hash for
	 * @param {Number} tree_size The tree_size of the tree on which to base the proof in decimal
	 * @return {Promise<Object.<leaf_index, audit_path>>}
	 */
	async get_proof_by_hash(hash, tree_size)
	{
		//region Initial variables
		const api = "get-proof-by-hash";
		
		let _hash;
		//endregion
		
		//region Calculate correct hash for passing to API
		if("byteLength" in hash)
			_hash = hash;
		else
			_hash = await hash.hash();
		//endregion
		
		/**
		 * @type {Object}
		 * @property {Number} leaf_index The 0-based index of the end entity corresponding to the "hash" parameter
		 * @property {Array} audit_path An array of base64-encoded Merkle Tree nodes proving the inclusion of the chosen certificate
		 */
		const json = await this.fetch(`${this.url}/${api}?hash=${this.encode(toBase64(arrayBufferToString(_hash)))}&tree_size=${tree_size}`)
			.then(handleResult(api), handleError(api));
		
		return {
			leaf_index: json.leaf_index,
			audit_path: Array.from(json.audit_path, element => stringToArrayBuffer(fromBase64(element)))
		};
	}
	//**********************************************************************************
	/**
	 * Implement call to "get-entries" Certificate Transparency Log API
	 * @param {Number} start 0-based index of first entry to retrieve, in decimal
	 * @param {Number} end 0-based index of last entry to retrieve, in decimal
	 * @param {Boolean} [request=true] Request or not additional absent entries
	 * @param {Boolean} [getX509=true] Get or not X.509 certificate entries
	 * @param {Boolean} [getPreCert=true] Get or not pre-certificate entries
	 * @return {Promise<Array>}
	 */
	async get_entries_raw(start, end, request = true, getX509 = true, getPreCert = true)
	{
		//region Initial variables
		const api = "get-entries";
		
		const entriesArray = [];
		//endregion
		
		/**
		 * @typedef entry
		 * @type {Object}
		 * @property {String} leaf_input The base64-encoded MerkleTreeLeaf structure
		 * @property {String} extra_data The base64-encoded unsigned data pertaining to the log entry
		 * @type {Object}
		 * @property {Array.<entry>} entries An array of objects
		 */
		const json = await this.fetch(`${this.url}/${api}?start=${start}&end=${end}`)
			.then(handleResult(api), handleError(api));
		
		for(const entry of json.entries)
		{
			//region Initial variables
			let extraData;
			
			const stream = new SeqStream({
				buffer: stringToArrayBuffer(fromBase64(entry.extra_data))
			});
			//endregion
			
			const merkleTreeLeaf = new MerkleTreeLeaf({
				stream: new SeqStream({
					buffer: stringToArrayBuffer(fromBase64(entry.leaf_input))
				})
			});

			switch(merkleTreeLeaf.entry.entryType)
			{
				case LogEntryType.constants("x509_entry"):
					{
						if(getX509 === false)
							continue;
						
						extraData = [];
						
						stream.getUint24(); // Overall data length, useless at the moment
						
						while(stream.length)
						{
							const certificateLength = stream.getUint24();
							const certificateBlock = (new Uint8Array(stream.getBlock(certificateLength))).buffer.slice(0);
							
							extraData.push(certificateBlock);
						}
					}
					break;
				case LogEntryType.constants("precert_entry"):
					{
						if(getPreCert === false)
							continue;
						
						//region Get information about "pre_certificate" value
						const preCertificateLength = stream.getUint24();
						
						const preCertificate = (new Uint8Array(stream.getBlock(preCertificateLength))).buffer.slice(0);
						//endregion
						
						//region Get information about "precertificate_chain" array
						const preCertificateChain = [];
						
						stream.getUint24(); // Overall data length, useless at the moment
						
						while(stream.length)
						{
							const certificateLength = stream.getUint24();
							
							preCertificateChain.push((new Uint8Array(stream.getBlock(certificateLength))).buffer.slice(0));
						}
						//endregion
						
						extraData = {
							pre_certificate: preCertificate,
							precertificate_chain: preCertificateChain
						};
					}
					break;
				default:
			}
			
			entriesArray.push({
				leaf: merkleTreeLeaf,
				extra_data: extraData
			});
		}
		
		//region Check we have all requested entries (some CT logs could return only a part)
		if(request && (entriesArray.length))
		{
			const least = entriesArray[entriesArray.length - 1];
			
			try
			{
				const proof = await this.get_proof_by_hash(least.leaf, end);
				if(proof.leaf_index !== end)
				{
					const additionalEntries = await this.get_entries_raw(proof.leaf_index + 1, end, request, getX509, getPreCert);
					entriesArray.push(...additionalEntries);
				}
			}
			catch(ex){}
		}
		//endregion
		
		return entriesArray;
	}
	//**********************************************************************************
	/**
	 * Implement call to "get-entries" Certificate Transparency Log API
	 * @param {Number} start 0-based index of first entry to retrieve, in decimal
	 * @param {Number} end 0-based index of last entry to retrieve, in decimal
	 * @param {Boolean} [request=true] Request or not additional absent entries
	 * @param {Boolean} [getX509=true] Get or not X.509 certificate entries
	 * @param {Boolean} [getPreCert=true] Get or not pre-certificate entries
	 * @return {Promise<Array>}
	 */
	async get_entries(start, end, request = true, getX509 = true, getPreCert = true)
	{
		const result = [];
		
		const entries = await this.get_entries_raw(start, end, request, getX509, getPreCert);
		
		for(const entry of entries)
		{
			let extraData;
			
			switch(entry.leaf.entry.entryType)
			{
				case LogEntryType.constants("x509_entry"):
					{
						if(getX509 === false)
							continue;
						
						extraData = [];
						
						for(const certificate of entry.extra_data)
						{
							const asn1 = asn1js.fromBER(certificate);
							if(asn1.offset === (-1))
								throw new Error("Object's stream was not correct for MerkleTreeLeaf extra_data");
							
							extraData.push(new Certificate({ schema: asn1.result }));
						}
					}
					break;
				case LogEntryType.constants("precert_entry"):
					{
						if(getPreCert === false)
							continue;
						
						//region Get information about "pre_certificate" value
						const asn1 = asn1js.fromBER(entry.extra_data.pre_certificate);
						if(asn1.offset === (-1))
							throw new Error("Object's stream was not correct for MerkleTreeLeaf extra_data");
						
						const preCertificate = new Certificate({ schema: asn1.result });
						//endregion
						
						//region Get information about "precertificate_chain" array
						const preCertificateChain = [];
						
						for(const preCertificateChainElement of entry.extra_data.precertificate_chain)
						{
							const asn1 = asn1js.fromBER(preCertificateChainElement);
							if(asn1.offset === (-1))
								throw new Error("Object's stream was not correct for MerkleTreeLeaf extra_data");
							
							preCertificateChain.push(new Certificate({ schema: asn1.result }));
						}
						//endregion
						
						extraData = {
							pre_certificate: preCertificate,
							precertificate_chain: preCertificateChain
						};
					}
					break;
				default:
			}
			
			result.push({
				leaf: entry.leaf,
				extra_data: extraData
			});
		}
		
		return result;
	}
	//**********************************************************************************
	/**
	 * Implement call to "get-entries" Certificate Transparency Log API and return leafs only
	 * @param {Number} start 0-based index of first entry to retrieve, in decimal
	 * @param {Number} end 0-based index of last entry to retrieve, in decimal
	 * @param {Boolean} [request=true] Request or not additional absent entries
	 * @return {Promise<Array>}
	 */
	async get_leafs(start, end, request = true)
	{
		//region Initial variables
		const api = "get-entries";
		//endregion
		
		/**
		 * @typedef entry
		 * @type {Object}
		 * @property {String} leaf_input The base64-encoded MerkleTreeLeaf structure
		 * @property {String} extra_data The base64-encoded unsigned data pertaining to the log entry
		 * @type {Object}
		 * @property {Array.<entry>} entries An array of objects
		 */
		const json = await this.fetch(`${this.url}/${api}?start=${start}&end=${end}`)
			.then(handleResult(api), handleError(api));
		
		//region Make major result array
		const result = Array.from(json.entries, element => new MerkleTreeLeaf({
			stream: new SeqStream({
				buffer: stringToArrayBuffer(fromBase64(element.leaf_input))
			})
		}));
		//endregion
		
		//region Check we have all requested entries (some CT logs could return only a part)
		if(request && (result.length > 0))
		{
			try
			{
				const proof = await this.get_proof_by_hash(result[result.length - 1], end);
				if(proof.leaf_index !== end)
				{
					const additionalEntries = await this.get_leafs(proof.leaf_index + 1, end, request);
					result.push(...additionalEntries);
				}
			}
			catch(ex){}
		}
		//endregion

		return result;
	}
	//**********************************************************************************
	/**
	 * Implement call to "get-roots" Certificate Transparency Log API
	 * @return {Promise<Array.<Certificate>>}
	 */
	async get_roots()
	{
		const api = "get-roots";
		
		/**
		 * @type {Object}
		 * @property {Array} certificates An array of base64-encoded root certificates that are acceptable to the log
		 */
		const json = await this.fetch(`${this.url}/${api}`)
			.then(handleResult(api), handleError(api));
		
		return Array.from(json.certificates, element =>
		{
			const asn1 = asn1js.fromBER(stringToArrayBuffer(fromBase64(element)));
			if(asn1.offset === (-1))
				throw new Error("Incorrect data returned after get-roots call");
			
			return (new Certificate({ schema: asn1.result }));
		});
	}
	//**********************************************************************************
	/**
	 * Implement call to "get-entry-and-proof" Certificate Transparency Log API
	 * @param {Number} leaf_index The index of the desired entry
	 * @param {Number} tree_size The tree_size of the tree for which the proof is
	 * @return {Promise<Object>}
	 */
	async get_entry_and_proof(leaf_index, tree_size)
	{
		//region Initial variables
		const api = "get-entry-and-proof";
		//endregion
		
		/**
		 * @type {Object}
		 * @property {String} leaf The base64-encoded MerkleTreeLeaf structure
		 * @property {String} extra_data The base64-encoded unsigned data pertaining to the log entry
		 * @property {Array.<String>} audit_path An array of base64-encoded Merkle Tree nodes proving the inclusion of the chosen certificate
		 */
		const json = await this.fetch(`${this.url}/${api}?leaf_index=${leaf_index}&tree_size=${tree_size}`)
			.then(handleResult(api), handleError(api));
		
		//region Initial variables
		let extraData;
		
		const stream = new SeqStream({
			buffer: stringToArrayBuffer(fromBase64(json.extra_data))
		});
		//endregion
		
		const merkleTreeLeaf = new MerkleTreeLeaf({
			stream: new SeqStream({
				buffer: stringToArrayBuffer(fromBase64(json.leaf))
			})
		});
		
		switch(merkleTreeLeaf.entry.entryType)
		{
			case 0:
				{
					extraData = [];
					
					stream.getUint24(); // Overall data length, useless at the moment
					
					while(stream.length)
					{
						const certificateLength = stream.getUint24();
						
						const asn1 = asn1js.fromBER((new Uint8Array(stream.getBlock(certificateLength))).buffer.slice(0));
						if(asn1.offset === (-1))
							throw new Error("Object's stream was not correct for MerkleTreeLeaf extra_data");
						
						extraData.push(new Certificate({ schema: asn1.result }));
					}
				}
				break;
			case 1:
				{
					//region Get information about "pre_certificate" value
					const preCertificateLength = stream.getUint24();
					
					const asn1 = asn1js.fromBER((new Uint8Array(stream.getBlock(preCertificateLength))).buffer.slice(0));
					if(asn1.offset === (-1))
						throw new Error("Object's stream was not correct for MerkleTreeLeaf extra_data");
					
					const preCertificate = new Certificate({ schema: asn1.result });
					//endregion
					
					//region Get information about "precertificate_chain" array
					const preCertificateChain = [];
					
					stream.getUint24(); // Overall data length, useless at the moment
					
					while(stream.length)
					{
						const certificateLength = stream.getUint24();
						
						const asn1 = asn1js.fromBER((new Uint8Array(stream.getBlock(certificateLength))).buffer.slice(0));
						if(asn1.offset === (-1))
							throw new Error("Object's stream was not correct for MerkleTreeLeaf extra_data");
						
						preCertificateChain.push(new Certificate({ schema: asn1.result }));
					}
					//endregion
					
					extraData = {
						pre_certificate: preCertificate,
						precertificate_chain: preCertificateChain
					};
				}
				break;
			default:
		}
		
		return {
			leaf: merkleTreeLeaf,
			extra_data: extraData,
			audit_path: Array.from(json.audit_path, element => stringToArrayBuffer(fromBase64(element)))
		};
	}
	//**********************************************************************************
}
//**************************************************************************************
