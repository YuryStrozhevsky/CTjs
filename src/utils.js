/* eslint-disable no-constant-condition */
import * as asn1js from "asn1js";
import { utilConcatBuf, isEqualBuffer, utilToBase, utilFromBase } from "pvutils";
import { getCrypto } from "pkijs";
//**************************************************************************************
export class utils
{
	//**********************************************************************************
	constructor()
	{
		throw new Error("Only calls to static functions allowed for namespace 'utils'");
	}
	//**********************************************************************************
	/**
	 * Calculating hash of two chilren leafs
	 * @param {MerkleTreeLeaf|ArrayBuffer} left
	 * @param {MerkleTreeLeaf|ArrayBuffer} right
	 * @param {String} [hashName=SHA-256] Name of hashing function, default SHA-256
	 * @return {Promise<ArrayBuffer>}
	 */
	static async hashChildren(left, right, hashName = "SHA-256")
	{
		//region Initial variables
		let leftHash;
		let rightHash;
		//endregion
		
		//region Get a "crypto" extension
		const crypto = getCrypto();
		if(typeof crypto === "undefined")
			throw new Error("Unable to create WebCrypto object");
		//endregion
		
		//region Correctly initialize "left" hash
		if("byteLength" in left)
			leftHash = left;
		else
			leftHash = await left.hash(hashName);
		//endregion
		
		//region Correctly initialize "right" hash
		if("byteLength" in right)
			rightHash = right;
		else
			rightHash = await right.hash(hashName);
		//endregion
		
		const prefixedBuffer = utilConcatBuf((new Uint8Array([0x01])).buffer, leftHash, rightHash);
		
		return await crypto.digest({ name: hashName }, prefixedBuffer);
	}
	//**********************************************************************************
	/**
	 * Nearest power of 2 less than "length" (got it here: https://stackoverflow.com/questions/2679815/previous-power-of-2)
	 * @param {Number} v Value for which computation will be performed
	 * @return {Number}
	 */
	static flp2(v)
	{
		let k = v;
		
		if(k && !(k & (k - 1)))
			k >>= 1;
		else
		{
			k |= (k >> 1);
			k |= (k >> 2);
			k |= (k >> 4);
			k |= (k >> 8);
			k |= (k >> 16);
			
			k -= (k >> 1);
		}
		
		return k;
	}
	//**********************************************************************************
	/**
	 * Calculate a Tree Head Given Proofs (RFC6962-bis, 2.1.3.2)
	 * @param {ArrayBuffer|MerkleTreeLeaf} hash MerkleTreeLeaf object or hash of the MerkleTreeLeaf
	 * @param {Number} index Index of the MerkleTreeLeaf
	 * @param {Number} treeSize The Merkle tree size to which we need to proof existance
	 * @param {Array.<ArrayBuffer>} proof Array of hashes with proof
	 * @param {String} [hashName=SHA-256] Name of hashing function, default SHA-256
	 * @return {Promise<Object>} Object(r:ArrayBuffer, sn:Number)
	 */
	static async calculateRootHashByProof(hash, index, treeSize, proof, hashName = "SHA-256")
	{
		//region Initial variables
		let fn = index;
		let sn = (treeSize - 1);
		let r;
		
		if("byteLength" in hash)
			r = hash;
		else
			r = await hash.hash(hashName);
		//endregion
		
		//region Check leaf index
		if(index >= treeSize)
			return false; //throw new Error(`Incorrect index=${index} for the treeSize=${treeSize}`);
		//endregion
		
		//region Perform verification for all proofs from the array
		for(const p of proof)
		{
			if(sn === 0)
				return false; //throw new Error("Proof verification failed");
			
			if((fn & 1) || (fn === sn))
			{
				r = await utils.hashChildren(p, r, hashName);
				
				if((fn & 1) === 0)
				{
					while(true)
					{
						fn >>= 1;
						sn >>= 1;
						
						if((fn & 1) || (fn === 0))
							break;
					}
				}
			}
			else
				r = await utils.hashChildren(r, p, hashName);
			
			fn >>= 1;
			sn >>= 1;
		}
		//endregion
		
		return {
			r,
			sn
		};
	}
	//**********************************************************************************
	/**
	 * Verifying an Inclusion Proof for any MerkleTreeLeaf with specified index (RFC6962-bis, 2.1.3.2)
	 * @param {ArrayBuffer|MerkleTreeLeaf} hash MerkleTreeLeaf object or hash of the MerkleTreeLeaf
	 * @param {Number} index Index of the MerkleTreeLeaf
	 * @param {Number} treeSize The Merkle tree size to which we need to proof existance
	 * @param {ArrayBuffer} rootHash Hash of the root to compare with
	 * @param {Array.<ArrayBuffer>} proof Array of hashes with proof
	 * @param {String} [hashName=SHA-256] Name of hashing function, default SHA-256
	 * @return {Promise<boolean>}
	 */
	static async verifyInclusionProof(hash, index, treeSize, rootHash, proof, hashName = "SHA-256")
	{
		const calculatedRootHash = await utils.calculateRootHashByProof(hash, index, treeSize, proof, hashName);
		
		return ((calculatedRootHash.sn === 0) && isEqualBuffer(calculatedRootHash.r, rootHash));
	}
	//**********************************************************************************
	/**
	 * Verifying Consistency between Two Tree Heads (RFC6962-bis, 2.1.4.2)
	 * @param {Number} first First tree size to compare
	 * @param {ArrayBuffer} firstHash Hash of the root for first tree size
	 * @param {Number} second Second tree size to compare
	 * @param {ArrayBuffer} secondHash Hash of the root for second tree size
	 * @param {Array.<ArrayBuffer>} consistency Array of hashes necessary for consistency verification
	 * @param {String} [hashName=SHA-256] Name of hashing function, default SHA-256
	 * @return {Promise<boolean>}
	 */
	static async verifyConsistency(first, firstHash, second, secondHash, consistency, hashName = "SHA-256")
	{
		//region Check input values
		if(first === second)
			return isEqualBuffer(firstHash, secondHash);
		//endregion
		
		//region Initial variables
		if(first && !(first & (first - 1))) // Check "first" for being power of 2
			consistency = [firstHash, ...consistency];
		
		let fn = (first - 1);
		let sn = (second - 1);
		
		if(fn & 1)
		{
			do
			{
				fn >>= 1;
				sn >>= 1;
			}while(fn & 1);
		}
		
		let fr = consistency[0];
		let sr = consistency[0];
		//endregion
		
		//region Calculate consistency hashes
		for(let i = 1; i < consistency.length; i++)
		{
			if(sn === 0)
				return false; //throw new Error("Consistency verification failed");
			
			if((fn & 1) || (fn === sn))
			{
				fr = await utils.hashChildren(consistency[i], fr, hashName);
				sr = await utils.hashChildren(consistency[i], sr, hashName);
				
				if((fn & 1) === 0)
				{
					while(true)
					{
						fn >>= 1;
						sn >>= 1;
						
						if((fn & 1) || (fn === 0))
							break;
					}
				}
			}
			else
				sr = await utils.hashChildren(sr, consistency[i], hashName);
			
			fn >>= 1;
			sn >>= 1;
		}
		//endregion
		
		return (isEqualBuffer(fr, firstHash) && isEqualBuffer(sr, secondHash) && (sn === 0));
	}
	//**********************************************************************************
	/**
	 * Calculate a Tree Head Given Entries (RFC6962-bis, 2.1.2 (modified))
	 * @param {Array.<MerkleTreeLeaf|ArrayBuffer>} entries Array of entries to verify against
	 * @param {String} [hashName=SHA-256] Name of hashing function, default SHA-256
	 * @param {?ArrayBuffer} [root] If not null tree root would be built starting from the "root"
	 * @param {?Number} [size] Tree size at which we got the "root". ONLY EVEN SIZES ALLOWED.
	 * @return {Promise<ArrayBuffer>}
	 */
	static async calculateRootHashByEntries(entries, hashName = "SHA-256", root = null, size = 0)
	{
		//region Initial variables
		const stack = [];
		//endregion
		
		//region Check we have "root" set
		if(root !== null)
		{
			if((size & 1) === 0)
				throw new Error("Calculation new root from old root possible only for even tree sizes");

			stack.push(root);
		}
		//endregion
		
		for(let i = size; i < (size + entries.length); i++)
		{
			//region Initial variables
			let merge_count = 0;
			let entryHash;
			//endregion

			if("byteLength" in entries[i - size])
				entryHash = entries[i - size];
			else
				entryHash = await entries[i - size].hash(hashName);
			
			stack.push(entryHash);
			
			// noinspection JSBitwiseOperatorUsage
			while((i >> merge_count) & 1)
				merge_count++;
			
			for(let j = 0; j < merge_count; j++)
			{
				const right = stack.pop();
				const left = stack.pop();
				const hash = await utils.hashChildren(left, right, hashName);
				
				stack.push(hash);
			}
		}
		
		if(stack.length > 1)
		{
			do
			{
				const right = stack.pop();
				const left = stack.pop();
				const hash = await utils.hashChildren(left, right, hashName);
				
				stack.push(hash);
			}while(stack.length > 1);
		}
		
		return stack.pop();
	}
	//**********************************************************************************
	// noinspection JSUnusedGlobalSymbols
	/**
	 * Verifying a Tree Head Given Entries (RFC6962-bis, 2.1.2)
	 * @param {Array.<MerkleTreeLeaf|ArrayBuffer>} entries Array of entries to verify against
	 * @param {ArrayBuffer} rootHash Root hash to compare
	 * @param {String} [hashName=SHA-256] Name of hashing function, default SHA-256
	 * @return {Promise<boolean>}
	 */
	static async verifyTreeHeadGivenEntries(entries, rootHash, hashName = "SHA-256")
	{
		const calculatedRootHash = await utils.calculateRootHashByEntries(entries, hashName);
		
		return isEqualBuffer(calculatedRootHash, rootHash);
	}
	//**********************************************************************************
	/**
	 * Calculate MTH function (RFC6962-bis, 2.1.1)
	 * @param {Array.<MerkleTreeLeaf|ArrayBuffer>} leafs Array of Merkle Tree Leafs
	 * @param {String} [hashName=SHA-256] Name of hashing function, default SHA-256
	 * @return {Promise<ArrayBuffer>}
	 */
	static async MTH(leafs, hashName = "SHA-256")
	{
		//region Get a "crypto" extension
		const crypto = getCrypto();
		if(typeof crypto === "undefined")
			throw new Error("Unable to create WebCrypto object");
		//endregion
		
		//region Special case for empty leaf's list
		if(leafs.length === 0)
			return crypto.digest({ name: hashName }, new ArrayBuffer(0));
		//endregion
		
		//region Check special cases
		switch(leafs.length)
		{
			case 0:
				return crypto.digest({ name: hashName }, new ArrayBuffer(0));
			case 1:
				if("byteLength" in leafs[0])
					return leafs[0];
				
				return leafs[0].hash(hashName);
			default:
		}
		//endregion
		
		//region Calculate nearest power of 2
		const k = utils.flp2(leafs.length);
		//endregion
		
		//region Recursivelly calculate "left" and "right"
		const left = await utils.MTH(leafs.slice(0, k));
		const right = await utils.MTH(leafs.slice(k));
		//endregion
		
		return utils.hashChildren(left, right, hashName);
	}
	//**********************************************************************************
	/**
	 * Calculate PATH function (RFC6962-bis, 2.1.3.1)
	 * @param {Number} index Zero-based index of item to find path for
	 * @param {Array.<MerkleTreeLeaf>} leafs Array of Merkle Tree Leafs
	 * @param {String} [hashName=SHA-256] Name of hashing function, default SHA-256
	 * @return {Promise<Array.<ArrayBuffer>>}
	 */
	static async PATH(index, leafs, hashName = "SHA-256")
	{
		//region Iniital variables
		let mth;
		let path;
		//endregion
		
		//region Check special case
		if((index === 0) && (leafs.length === 1))
			return [];
		//endregion
		
		//region Calculate nearest power of 2
		const k = utils.flp2(leafs.length);
		//endregion
		
		if(index < k)
		{
			mth = await utils.MTH(leafs.slice(k), hashName);
			path = await utils.PATH(index, leafs.slice(0, k), hashName);
		}
		else
		{
			mth = await utils.MTH(leafs.slice(0, k), hashName);
			path = await utils.PATH(index - k, leafs.slice(k), hashName);
		}
		
		return [...path, mth];
	}
	//**********************************************************************************
	/**
	 * Calculate SYBPROOF function (RFC6962-bis, 2.1.4.1)
	 * @param {Number} size Tree size to find consistency proof for
	 * @param {Array.<MerkleTreeLeaf>} leafs Array of Merkle Tree Leafs
	 * @param {Boolean} b Value represents whether the subtree created from D[0:m] is a complete subtree of the Merkle Tree
	 * @param {String} [hashName=SHA-256] Name of hashing function, default SHA-256
	 * @return {Promise<Array.<ArrayBuffer>>}
	 */
	static async SUBPROOF(size, leafs, b, hashName = "SHA-256")
	{
		//region Initial variables
		let mth;
		let proof;
		//endregion
		
		//region Check input values
		if(size > leafs.length)
			return [];
		//endregion
		
		//region Check special cases
		if((size === leafs.length) && (b === true))
			return [];
		
		if((size === leafs.length) && (b === false))
			return [await utils.MTH(leafs, hashName)];
		//endregion
		
		//region Calculate nearest power of 2
		const k = utils.flp2(leafs.length);
		//endregion
		
		if(size <= k)
		{
			mth = await utils.MTH(leafs.slice(k), hashName);
			proof = await utils.SUBPROOF(size, leafs.slice(0, k), b, hashName);
		}
		else
		{
			mth = await utils.MTH(leafs.slice(0, k), hashName);
			proof = await utils.SUBPROOF(size - k, leafs.slice(k), false, hashName);
		}
		
		return [...proof, mth];
	}
	//**********************************************************************************
	/**
	 * Calculate PROOF function (RFC6962-bis, 2.1.4.1)
	 * @param {Number} size Tree size to find consistency proof for
	 * @param {Array.<MerkleTreeLeaf>} leafs Array of Merkle Tree Leafs
	 * @param {String} [hashName=SHA-256] Name of hashing function, default SHA-256
	 * @return {Promise<Array.<ArrayBuffer>>}
	 */
	static async PROOF(size, leafs, hashName = "SHA-256")
	{
		//region Check input values
		if(size === 0)
			return [];
		//endregion
		
		return utils.SUBPROOF(size, leafs, true, hashName);
	}
	//**********************************************************************************
	/**
	 * Get numeric representation of 8-byte value in SeqStream
	 * @param {SeqStream} stream The SeqStream object to read the value from
	 * @return {number}
	 */
	static getUint64(stream)
	{
		return utilFromBase(new Uint8Array(stream.getBlock(8)), 8);
	}
	//**********************************************************************************
	/**
	 * Append 8-byte buffer with representation of numeric value
	 * @param {Number} value The value for conversion
	 * @param {SeqStream} stream The SeqStream object to be updated
	 */
	static appendUint64(value, stream)
	{
		const valueBuffer = new ArrayBuffer(8);
		const valueView = new Uint8Array(valueBuffer);
		
		const baseArray = utilToBase(value, 8);
		valueView.set(new Uint8Array(baseArray), 8 - baseArray.byteLength);
		
		stream.appendView(valueView);
	}
	//**********************************************************************************
	/**
	 * Get string representation of OID stored in SeqStream
	 * @param stream
	 * @param objectName
	 * @return {string}
	 */
	static getOID(stream, objectName)
	{
		const oidLength = (stream.getBlock(1))[0];
		
		const asn1 = asn1js.fromBER((new Uint8Array(stream.getBlock(oidLength))).buffer.slice(0));
		if(asn1.offset === (-1))
			throw new Error(`Object's stream was not correct for ${objectName}`);
		
		return asn1.result.valueBlock.toString();
	}
	//**********************************************************************************
	/**
	 * Append OID representation to SeqStream
	 * @param {String} value String representation of the OID
	 * @param {SeqStream} stream The SeqStream object to be updated
	 */
	static appendOID(value, stream)
	{
		const oid = new asn1js.ObjectIdentifier({ value });
		const oidBER = oid.toBER(false);
		
		stream.appendChar(oidBER.byteLength);
		stream.appendView(new Uint8Array(oidBER));
	}
	//**********************************************************************************
}
//**************************************************************************************
