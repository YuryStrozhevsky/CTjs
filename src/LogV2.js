/* eslint-disable no-useless-escape */
import * as asn1js from "asn1js";
import { getParametersValue, stringToArrayBuffer, fromBase64 } from "pvutils";
import { SeqStream } from "bytestreamjs";
import { PublicKeyInfo } from "pkijs";
import TransItem from "./TransItem.js";
//**************************************************************************************
export default class LogV2
{
	//**********************************************************************************
	/**
	 * Constructor for LogV2 class
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
		this.fetch = getParametersValue(parameters, "fetch", LogV2.constants("fetch"));
		/**
		 * @type {Function}
		 * @description encode
		 */
		this.encode = getParametersValue(parameters, "encode", LogV2.constants("encode"));
		
		/**
		 * @type {String}
		 * @description url
		 */
		this.url = getParametersValue(parameters, "url", LogV2.constants("url"));
		/**
		 * @type {String}
		 * @description hashAlgorithm
		 */
		this.hashAlgorithm = getParametersValue(parameters, "hashAlgorithm", LogV2.constants("hashAlgorithm"));
		/**
		 * @type {String}
		 * @description signatureAlgorithm
		 */
		this.signatureAlgorithm = getParametersValue(parameters, "signatureAlgorithm", LogV2.constants("signatureAlgorithm"));
		
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
		
		if("log_id" in parameters)
		{
			/**
			 * @type {String}
			 * @description logID
			 */
			this.logID = getParametersValue(parameters, "log_id", LogV2.constants("logID"));
		}
		
		if("maximum_merge_delay" in parameters)
		{
			/**
			 * @type {Number}
			 * @description maximumMergeDelay
			 */
			this.maximumMergeDelay = getParametersValue(parameters, "maximum_merge_delay", LogV2.constants("maximumMergeDelay"));
		}
		
		if("final_sth" in parameters)
		{
			this.finalSTH = {
				treeSize: parameters.final_sth.tree_size,
				timestamp: new Date(parameters.final_sth.timestamp),
				rootHash: stringToArrayBuffer(fromBase64(parameters.final_sth.sha256_root_hash)),
				signature: new TransItem({
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
				return async () => { return Promise.reject("Uninitialized fetch function for LogV2 class"); };
			case "encode":
				return () => { throw new Error("Uninitialized encode function for LogV2 class"); };
			case "url":
				return "";
			case "hashAlgorithm":
				return "SHA-256";
			case "signatureAlgorithm":
				return "ECDSA";
			case "logID":
				return "";
			case "maximumMergeDelay":
				return 0;
			default:
				throw new Error(`Invalid constant name for LogV2 class: ${name}`);
		}
	}
	//**********************************************************************************
	set url(value)
	{
		if(value === "")
			return;
		
		const match = value.match(/(?:http[s]?:\/\/)?([^?\/s]+.*)/);
		if(match === null)
			throw new Error("Base URL for LogV2 class must be set to a correct value");
		
		this._url = `https://${match[1].replace(/\/*$/g, "")}/ct/v2`;
	}
	//**********************************************************************************\
	get url()
	{
		return this._url;
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
			.then(result =>
			{
				if(result.ok)
					return result.json();
				
				return Promise.reject(`ERROR while fetching ${api}: ${result.statusText}`);
			});
		
		return json;
	}
	//**********************************************************************************
}
//**************************************************************************************
