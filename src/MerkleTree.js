import { getParametersValue, toBase64, arrayBufferToString, isEqualBuffer } from "pvutils";
import { utils } from "./utils.js";
//**************************************************************************************
export default class MerkleTree 
{
	//**********************************************************************************
	/**
	 * Constructor for MerkleTree class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {Array.<MerkleTreeLeaf|ArrayBuffer|TransItem>}
		 * @description leafs Array of leafs for the tree
		 */
		this.leafs = getParametersValue(parameters, "leafs", MerkleTree.constants("leafs"));
		/**
		 * @type {Array.<Array.<ArrayBuffer>>}
		 * @description nodes Array of array of nodes (calculated hashes) for the tree
		 * Each subarray represents next node level.
		 */
		this.nodes = getParametersValue(parameters, "nodes", MerkleTree.constants("nodes"));
		/**
		 * @type {String}
		 * @description hashName Name of hashing function to apply, default = SHA-256
		 */
		this.hashName = getParametersValue(parameters, "hashName", MerkleTree.constants("hashName"));
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
			case "leafs":
			case "nodes":
				return [];
			case "hashName":
				return "SHA-256";
			default:
				throw new Error(`Invalid constant name for MerkleTree class: ${name}`);
		}
	}
	//**********************************************************************************
	/**
	 * Inialize Merkle Tree using provided set of Merkle Tree Leafs
	 * @param {Array.<MerkleTreeLeaf|ArrayBuffer|TransItem>} leafs Array of leafs for the tree
	 * @param {String} [hashName=SHA-256] Name of hashing function to apply, default = SHA-256
	 * @return {Promise<MerkleTree>}
	 */
	static async fromLeafs(leafs, hashName = "SHA-256")
	{
		//region Initial variables
		const result = new MerkleTree({ leafs, hashName });
		
		const stack = [];
		const nodes = [];
		//endregion
		
		//region Initialize first level of nodes
		for(let i = 0; i < result.leafs.length; i++)
		{
			const hash = await result.getHashByIndex(i);

			if(i & 1)
				nodes.push(await utils.hashChildren(stack.pop(), hash, result.hashName));
			else
				stack.push(hash);
		}
		
		if(stack.length)
			nodes.push(stack.pop());
		//endregion
		
		//region Initialize all nodes
		await result.initializeNodes(nodes);
		//endregion
		
		return result;
	}
	//**********************************************************************************
	/**
	 * Inialize nodes in Merkle Tree given provided hashes from previous node's level
	 * @param {Array.<ArrayBuffer>} nodes Array of nodes from previous level
	 * @return {Promise<void>}
	 */
	async initializeNodes(nodes)
	{
		//region Initial variables
		const stack = [];
		const level = [];
		//endregion
		
		//region Put new level
		this.nodes.push(nodes);
		
		if((nodes.length === 1) || (nodes.length === 0))
			return;
		//endregion
		
		//region Initialize another level
		for(let i = 0; i < nodes.length; i++)
		{
			if(i & 1)
				level.push(await utils.hashChildren(stack.pop(), nodes[i], this.hashName));
			else
				stack.push(nodes[i]);
		}
		//endregion
		
		//region Push remainder to one level up
		if(stack.length)
		{
			level.push(stack.pop());
			this.nodes[this.nodes.length - 1].pop();
		}
		//endregion

		await this.initializeNodes(level);
	}
	//**********************************************************************************
	/**
	 * Represent Merkle Tree as a array with BASE-64 encoded values
	 * @return {Promise<[String[]]>}
	 */
	async asBase64()
	{
		//region Initial variables
		const output = [[]];
		//endregion
		
		//region Store information about all leafs
		for(let i = 0; i < this.leafs.length; i++)
			output[0].push(toBase64(arrayBufferToString(await this.getHashByIndex(i))));
		//endregion
		
		//region Store information about all nodes
		for(const level of this.nodes)
			output.push(Array.from(level, element => toBase64(arrayBufferToString(element))));
		//endregion
		
		return output;
	}
	//**********************************************************************************
	/**
	 * Append array of Merkel Tree Leafs to current set of leafs
	 * @param {Array.<MerkleTreeLeaf|ArrayBuffer|TransItem>} array Array of Merkle Tree Leafs
	 * @return {Promise<void>}
	 */
	async append(array)
	{
		const temp = await MerkleTree.fromLeafs([this.leafs, ...array], this.hashName);
		
		this.leafs = temp.leafs.slice();
		this.nodes = temp.nodes.slice();
	}
	//**********************************************************************************
	/**
	 * Return hash for element given its index
	 * @param {Number} index Zero-based index of the element
	 * @return {Promise<ArrayBuffer>}
	 */
	async getHashByIndex(index)
	{
		//region Check input values
		if(index > (this.leafs.length - 1))
			return (new ArrayBuffer(0));
		//endregion
		
		if("byteLength" in this.leafs[index])
			return this.leafs[index];
		
		return this.leafs[index].hash(this.hashName);
	}
	//**********************************************************************************
	/**
	 * Get array with inclusion proof given hash of element
	 * @param {ArrayBuffer} hash Hash of existing element
	 * @return {Promise<Array.<ArrayBuffer>>}
	 */
	async getProofByHash(hash)
	{
		for(let i = 0; i < this.leafs.length; i++)
		{
			if(isEqualBuffer(hash, await this.getHashByIndex(i)))
				return this.getProofByIndex(i);
		}
		
		return [];
	}
	//**********************************************************************************
	/**
	 * Get array with inclusion proof given index of element
	 * @param {Number} index Zero-based index of existing element
	 * @return {Promise<Array.<ArrayBuffer>>}
	 */
	async getProofByIndex(index)
	{
		return utils.PATH(index, this.leafs, this.hashName);
	}
	//**********************************************************************************
	/**
	 * Verifying an Inclusion Proof for any MerkleTreeLeaf with specified index (RFC6962-bis, 2.1.3.2)
	 * @param {ArrayBuffer|MerkleTreeLeaf|TransItem} hash MerkleTreeLeaf object or hash of the MerkleTreeLeaf
	 * @param {Number} treeSize The Merkle tree size to which we need to proof existance
	 * @param {ArrayBuffer} rootHash Hash of the root to compare with
	 * @param {Array.<ArrayBuffer>} proof Array of hashes with proof
	 * @return {Promise<boolean>}
	 */
	async verifyProofByHash(hash, treeSize, rootHash, proof)
	{
		for(let i = 0; i < this.leafs.length; i++)
		{
			if(isEqualBuffer(hash, await this.getHashByIndex(i)))
				return this.verifyProofByIndex(i, treeSize, rootHash, proof);
		}
		
		return false;
	}
	//**********************************************************************************
	/**
	 * Verifying an Inclusion Proof for any MerkleTreeLeaf with specified index (RFC6962-bis, 2.1.3.2)
	 * @param {Number} index Index of MerkleTreeLeaf object
	 * @param {Number} treeSize The Merkle tree size to which we need to proof existance
	 * @param {ArrayBuffer} rootHash Hash of the root to compare with
	 * @param {Array.<ArrayBuffer>} proof Array of hashes with proof
	 * @return {Promise<boolean>}
	 */
	async verifyProofByIndex(index, treeSize, rootHash, proof)
	{
		const leafHash = await this.getHashByIndex(index);
		return utils.verifyInclusionProof(leafHash, index, treeSize, rootHash, proof, this.hashName);
	}
	//**********************************************************************************
	/**
	 * Get consistency proof given size of previous tree to compare with
	 * @param {Number} size Size of previous tree to compare with
	 * @return {Promise<Array.<ArrayBuffer>>}
	 */
	async getConsistency(size)
	{
		return utils.PROOF(size, this.leafs, this.hashName);
	}
	//**********************************************************************************
	/**
	 * Verifying Consistency between Two Tree Heads (RFC6962-bis, 2.1.4.2)
	 * @param {Number} first First tree size to compare
	 * @param {ArrayBuffer} firstHash Hash of the root for first tree size
	 * @param {Number} second Second tree size to compare
	 * @param {ArrayBuffer} secondHash Hash of the root for second tree size
	 * @param {Array.<ArrayBuffer>} consistency Array of hashes necessary for consistency verification
	 * @return {Promise<boolean>}
	 */
	async verifyConsistency(first, firstHash, second, secondHash, consistency)
	{
		return utils.verifyConsistency(first, firstHash, second, secondHash, consistency, this.hashName);
	}
	//**********************************************************************************
	/**
	 * Get hash of the tree head
	 * @return {Promise<ArrayBuffer>}
	 */
	async getRootHash()
	{
		return utils.MTH(this.leafs, this.hashName);
	}
	//**********************************************************************************
	/**
	 * Calculate a Tree Head Given Proofs (RFC6962-bis, 2.1.3.2)
	 * @param {Number} index Index of the MerkleTreeLeaf
	 * @param {Number} treeSize The Merkle tree size to which we need to proof existance
	 * @param {Array.<ArrayBuffer>} proof Array of hashes with proof
	 * @return {Promise<ArrayBuffer>}
	 */
	async getRootHashByProof(index, treeSize, proof)
	{
		const leafHash = await this.getHashByIndex(index);
		return utils.calculateRootHashByProof(leafHash, index, treeSize, proof, this.hashName);
	}
	//**********************************************************************************
}
//**************************************************************************************
