/*
* This example built on example, represented in RFC6962, item 2.1.3
*
* In the file all known Certificate Transparency Logs are requested
* for first 7 elements and for those element performing necessary tests.
* Names are the same with RFC6969 in order to better understanding.
*
*/

/* eslint-disable no-undef */
// noinspection JSUnresolvedFunction
import { fromBase64, stringToArrayBuffer, toBase64, arrayBufferToString } from "pvutils";
import LogV1 from "../../src/LogV1.js";
import { utils } from "../../src/utils.js";

const logs = require("./known-logs.js");

const fetch = require("node-fetch");
const encode = require("urlencode").encode;
const assert = require("assert");

import { CryptoEngine, setEngine } from "pkijs";

// noinspection NpmUsedModulesInstalled
const WebCrypto = require("node-webcrypto-ossl");
/**
 * @type {Object}
 * @property subtle
 */
const webcrypto = new WebCrypto();

setEngine("ossl-engine", webcrypto, new CryptoEngine({ name: "", crypto: webcrypto, subtle: webcrypto.subtle }));
//*********************************************************************************
context("Check all known logs with RFC6962 example's data", () =>
{
	for(const parameters of logs)
	{
		it(parameters.description, async () =>
		{
			//region Initial variables
			parameters.encode = encode;
			parameters.fetch = fetch;
			
			const log = new LogV1(parameters);
			
			const hashProofs = [];
			const calculatedRootHashes = [];
			//endregion
			
			//region Fetch necessary entries
			const entries = await log.get_entries(0, 6);
			//endregion

			//region Initialize variables from RFC6962, item 2.1.3 example
			const a = toBase64(arrayBufferToString(await entries[0].leaf.hash()));
			const b = toBase64(arrayBufferToString(await entries[1].leaf.hash()));
			const c = toBase64(arrayBufferToString(await entries[2].leaf.hash()));
			const d = toBase64(arrayBufferToString(await entries[3].leaf.hash()));
			const e = toBase64(arrayBufferToString(await entries[4].leaf.hash()));
			const f = toBase64(arrayBufferToString(await entries[5].leaf.hash()));
			const j = toBase64(arrayBufferToString(await entries[6].leaf.hash()));
			
			const g = toBase64(arrayBufferToString(await utils.hashChildren(stringToArrayBuffer(fromBase64(a)), stringToArrayBuffer(fromBase64(b)))));
			const h = toBase64(arrayBufferToString(await utils.hashChildren(stringToArrayBuffer(fromBase64(c)), stringToArrayBuffer(fromBase64(d)))));
			const i = toBase64(arrayBufferToString(await utils.hashChildren(stringToArrayBuffer(fromBase64(e)), stringToArrayBuffer(fromBase64(f)))));
			
			const k = toBase64(arrayBufferToString(await utils.hashChildren(stringToArrayBuffer(fromBase64(g)), stringToArrayBuffer(fromBase64(h)))));
			const l = toBase64(arrayBufferToString(await utils.hashChildren(stringToArrayBuffer(fromBase64(i)), stringToArrayBuffer(fromBase64(j)))));
			
			const hash = toBase64(arrayBufferToString(await utils.hashChildren(stringToArrayBuffer(fromBase64(k)), stringToArrayBuffer(fromBase64(l)))));
			//endregion
			
			//region Verify proof of inclusion for all element in the tree
			const proof_d0 = await log.get_proof_by_hash(entries[0].leaf, 7);
			const proof_d0Base64 = Array.from(proof_d0.audit_path, element => toBase64(arrayBufferToString(element)));
			assert.deepStrictEqual(proof_d0Base64, [b, h, l], "Proof of inclusion array for d0 is incorrect");
			const verificationProof_d0 = await utils.verifyInclusionProof(
				stringToArrayBuffer(fromBase64(a)),
				0,
				7,
				stringToArrayBuffer(fromBase64(hash)),
				proof_d0.audit_path
			);
			assert.deepStrictEqual(verificationProof_d0, true, "Proof of inclusion for d0 was not verified");
			
			const proof_d1 = await log.get_proof_by_hash(entries[1].leaf, 7);
			const proof_d1Base64 = Array.from(proof_d1.audit_path, element => toBase64(arrayBufferToString(element)));
			assert.deepStrictEqual(proof_d1Base64, [a, h, l], "Proof of inclusion array for d1 is incorrect");
			const verificationProof_d1 = await utils.verifyInclusionProof(
				stringToArrayBuffer(fromBase64(b)),
				1,
				7,
				stringToArrayBuffer(fromBase64(hash)),
				proof_d1.audit_path
			);
			assert.deepStrictEqual(verificationProof_d1, true, "Proof of inclusion for d1 was not verified");
			
			const proof_d2 = await log.get_proof_by_hash(entries[2].leaf, 7);
			const proof_d2Base64 = Array.from(proof_d2.audit_path, element => toBase64(arrayBufferToString(element)));
			assert.deepStrictEqual(proof_d2Base64, [d, g, l], "Proof of inclusion array for d2 is incorrect");
			const verificationProof_d2 = await utils.verifyInclusionProof(
				stringToArrayBuffer(fromBase64(c)),
				2,
				7,
				stringToArrayBuffer(fromBase64(hash)),
				proof_d2.audit_path
			);
			assert.deepStrictEqual(verificationProof_d2, true, "Proof of inclusion for d2 was not verified");
			
			const proof_d3 = await log.get_proof_by_hash(entries[3].leaf, 7);
			const proof_d3Base64 = Array.from(proof_d3.audit_path, element => toBase64(arrayBufferToString(element)));
			assert.deepStrictEqual(proof_d3Base64, [c, g, l], "Proof of inclusion array for d3 is incorrect");
			const verificationProof_d3 = await utils.verifyInclusionProof(
				stringToArrayBuffer(fromBase64(d)),
				3,
				7,
				stringToArrayBuffer(fromBase64(hash)),
				proof_d3.audit_path
			);
			assert.deepStrictEqual(verificationProof_d3, true, "Proof of inclusion for d3 was not verified");
			
			const proof_d4 = await log.get_proof_by_hash(entries[4].leaf, 7);
			const proof_d4Base64 = Array.from(proof_d4.audit_path, element => toBase64(arrayBufferToString(element)));
			assert.deepStrictEqual(proof_d4Base64, [f, j, k], "Proof of inclusion array for d4 is incorrect");
			const verificationProof_d4 = await utils.verifyInclusionProof(
				stringToArrayBuffer(fromBase64(e)),
				4,
				7,
				stringToArrayBuffer(fromBase64(hash)),
				proof_d4.audit_path
			);
			assert.deepStrictEqual(verificationProof_d4, true, "Proof of inclusion for d4 was not verified");
			
			const proof_d5 = await log.get_proof_by_hash(entries[5].leaf, 7);
			const proof_d5Base64 = Array.from(proof_d5.audit_path, element => toBase64(arrayBufferToString(element)));
			assert.deepStrictEqual(proof_d5Base64, [e, j, k], "Proof of inclusion array for d5 is incorrect");
			const verificationProof_d5 = await utils.verifyInclusionProof(
				stringToArrayBuffer(fromBase64(f)),
				5,
				7,
				stringToArrayBuffer(fromBase64(hash)),
				proof_d5.audit_path
			);
			assert.deepStrictEqual(verificationProof_d5, true, "Proof of inclusion for d5 was not verified");
			
			const proof_d6 = await log.get_proof_by_hash(entries[6].leaf, 7);
			const proof_d6Base64 = Array.from(proof_d6.audit_path, element => toBase64(arrayBufferToString(element)));
			assert.deepStrictEqual(proof_d6Base64, [i, k], "Proof of inclusion array for d6 is incorrect");
			const verificationProof_d6 = await utils.verifyInclusionProof(
				stringToArrayBuffer(fromBase64(j)),
				6,
				7,
				stringToArrayBuffer(fromBase64(hash)),
				proof_d6.audit_path
			);
			assert.deepStrictEqual(verificationProof_d6, true, "Proof of inclusion for d6 was not verified");
			//endregion
			
			//region Calculate possible root hashes for all tree sizes
			for(let i = 2; i <= 7; i++)
			{
				const rootProofs = await log.get_proof_by_hash(entries[0].leaf, i);
				hashProofs.push(rootProofs.audit_path);
			}
			
			for(let i = 0; i < hashProofs.length; i++)
				calculatedRootHashes.push(await utils.calculateRootHashByProof(entries[0].leaf, 0, i + 2, hashProofs[i]));
			
			const calculatedRootHashesBase64 = Array.from(calculatedRootHashes, element => toBase64(arrayBufferToString(element.r)));
			//endregion
			
			//region Calculate root hash by entries and check we have the same with calculated by proof
			const calculateRootByEntries = await utils.calculateRootHashByEntries(Array.from(entries, element => element.leaf));
			const calculateRootByEntriesBase64 = toBase64(arrayBufferToString(calculateRootByEntries));
			
			assert.deepStrictEqual(calculatedRootHashesBase64[5], calculateRootByEntriesBase64, "Root hashes calculated by proof and entries are not the same");
			//endregion
			
			//region Check calculated root hashes are same we expected
			assert.deepStrictEqual(calculatedRootHashesBase64[0], g, "Value for g was not verified");
			assert.deepStrictEqual(calculatedRootHashesBase64[2], k, "Value for k was not verified");
			assert.deepStrictEqual(calculatedRootHashesBase64[5], hash, "Value for hash was not verified");
			//endregion
			
			//region Check consistency for all possible start tree sizes
			//region Check consistency between "treeSize = 1" and "treeSize = 7"
			const consistency1_7 = await log.get_sth_consistency(1, 7);
			const consistency1_7Base64 = Array.from(consistency1_7, element => toBase64(arrayBufferToString(element)));
			assert.deepStrictEqual(consistency1_7Base64, [b, h, l], "Consistency array for (start:1, end:7) is incorrect");
			const verificationConsistency1_7 = await utils.verifyConsistency(
				1,
				stringToArrayBuffer(fromBase64(a)),
				7,
				stringToArrayBuffer(fromBase64(calculatedRootHashesBase64[5])),
				consistency1_7
			);
			assert.deepStrictEqual(verificationConsistency1_7, true, "Consistency check for (first:1, second:7) failed");
			//endregion
			
			//region Check consistency between "treeSize = 2" and "treeSize = 7"
			const consistency2_7 = await log.get_sth_consistency(2, 7);
			const consistency2_7Base64 = Array.from(consistency2_7, element => toBase64(arrayBufferToString(element)));
			assert.deepStrictEqual(consistency2_7Base64, [h, l], "Consistency array for (start:2, end:7) is incorrect");
			const verificationConsistency2_7 = await utils.verifyConsistency(
				2,
				stringToArrayBuffer(fromBase64(calculatedRootHashesBase64[0])),
				7,
				stringToArrayBuffer(fromBase64(calculatedRootHashesBase64[5])),
				consistency2_7
			);
			assert.deepStrictEqual(verificationConsistency2_7, true, "Consistency check for (first:2, second:7) failed");
			//endregion
			
			//region Check consistency between "treeSize = 3" and "treeSize = 7"
			const consistency3_7 = await log.get_sth_consistency(3, 7);
			const consistency3_7Base64 = Array.from(consistency3_7, element => toBase64(arrayBufferToString(element)));
			assert.deepStrictEqual(consistency3_7Base64, [c, d, g, l], "Consistency array for (start:3, end:7) is incorrect");
			const verificationConsistency3_7 = await utils.verifyConsistency(
				3,
				stringToArrayBuffer(fromBase64(calculatedRootHashesBase64[1])),
				7,
				stringToArrayBuffer(fromBase64(calculatedRootHashesBase64[5])),
				consistency3_7
			);
			assert.deepStrictEqual(verificationConsistency3_7, true, "Consistency check for (first:3, second:7) failed");
			//endregion
			
			//region Check consistency between "treeSize = 4" and "treeSize = 7"
			const consistency4_7 = await log.get_sth_consistency(4, 7);
			const consistency4_7Base64 = Array.from(consistency4_7, element => toBase64(arrayBufferToString(element)));
			assert.deepStrictEqual(consistency4_7Base64, [l], "Consistency array for (start:4, end:7) is incorrect");
			const verificationConsistency4_7 = await utils.verifyConsistency(
				4,
				stringToArrayBuffer(fromBase64(calculatedRootHashesBase64[2])),
				7,
				stringToArrayBuffer(fromBase64(calculatedRootHashesBase64[5])),
				consistency4_7
			);
			assert.deepStrictEqual(verificationConsistency4_7, true, "Consistency check for (first:4, second:7) failed");
			//endregion
			
			//region Check consistency between "treeSize = 5" and "treeSize = 7"
			const consistency5_7 = await log.get_sth_consistency(5, 7);
			const consistency5_7Base64 = Array.from(consistency5_7, element => toBase64(arrayBufferToString(element)));
			assert.deepStrictEqual(consistency5_7Base64, [e, f, j, k], "Consistency array for (start:5, end:7) is incorrect");
			const verificationConsistency5_7 = await utils.verifyConsistency(
				5,
				stringToArrayBuffer(fromBase64(calculatedRootHashesBase64[3])),
				7,
				stringToArrayBuffer(fromBase64(calculatedRootHashesBase64[5])),
				consistency5_7
			);
			assert.deepStrictEqual(verificationConsistency5_7, true, "Consistency check for (first:5, second:7) failed");
			//endregion
			
			//region Check consistency between "treeSize = 6" and "treeSize = 7"
			const consistency6_7 = await log.get_sth_consistency(6, 7);
			const consistency6_7Base64 = Array.from(consistency6_7, element => toBase64(arrayBufferToString(element)));
			assert.deepStrictEqual(consistency6_7Base64, [i, j, k], "Consistency array for (start:5, end:7) is incorrect");
			const verificationConsistency6_7 = await utils.verifyConsistency(
				6,
				stringToArrayBuffer(fromBase64(calculatedRootHashesBase64[4])),
				7,
				stringToArrayBuffer(fromBase64(calculatedRootHashesBase64[5])),
				consistency6_7
			);
			assert.deepStrictEqual(verificationConsistency6_7, true, "Consistency check for (first:6, second:7) failed");
			//endregion
			
			//region Check consistency between "treeSize = 7" and "treeSize = 7"
			const consistency7_7 = await log.get_sth_consistency(7, 7);
			assert.deepStrictEqual(consistency7_7.length, 0, `Incorrect length for consistency(start:7, end:7) - ${consistency7_7.length}`);
			const verificationConsistency7_7 = await utils.verifyConsistency(
				7,
				stringToArrayBuffer(fromBase64(calculatedRootHashesBase64[5])),
				7,
				stringToArrayBuffer(fromBase64(calculatedRootHashesBase64[5])),
				consistency7_7
			);
			assert.deepStrictEqual(verificationConsistency7_7, true, "Consistency check for (first:7, second:7) failed");
			//endregion
			//endregion
		});
	}
});
//*********************************************************************************
