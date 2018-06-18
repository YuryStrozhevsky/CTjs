/* eslint-disable no-undef */
// noinspection JSUnresolvedFunction
import { isEqualBuffer } from "pvutils";
import { SeqStream } from "bytestreamjs";
import { utils } from "../../src/utils.js";
import LogV1 from "../../src/LogV1.js";
import PreCert from "../../src/PreCert.js";
import LogEntryType from "../../src/LogEntryType.js";
import SignedCertificateTimestamp from "../../src/SignedCertificateTimestamp.js";

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
async function findIssuer(certificate, issuers)
{
	const result = issuers.slice();
	
	for(let i = 0; i < result.length; i++)
	{
		try
		{
			const verificationResult = await certificate.verify(result[i]);
			if(verificationResult)
				return result[i];
			
			result.splice(i, 1);
		}
		catch(ex)
		{
			result.splice(i, 1); // Something wrong, remove the certificate
		}
	}
	
	return null;
}
//*********************************************************************************
/**
 * Get flag could we verify any SCT in the certificate
 * @param {Certificate} certificate
 * @param {ArrayBuffer} logID
 * @return {SignedCertificateTimestamp|null}
 */
function sctFromCertificate(certificate, logID)
{
	let parsedValue = null;
	
	//region Remove certificate extension
	for(let i = 0; i < certificate.extensions.length; i++)
	{
		switch(certificate.extensions[i].extnID)
		{
			case "1.3.6.1.4.1.11129.2.4.2":
				{
					parsedValue = certificate.extensions[i].parsedValue;
					
					if(parsedValue.timestamps.length === 0)
						throw new Error("Nothing to verify in the certificate");
					
					certificate.extensions.splice(i, 1);
				}
				break;
			default:
		}
	}
	//endregion
	
	if(parsedValue !== null)
	{
		for(const timestamp of parsedValue.timestamps)
		{
			if(isEqualBuffer(timestamp.logID, logID))
			{
				const stream = new SeqStream({ buffer: timestamp.toStream().buffer }) ;
				return (new SignedCertificateTimestamp({ stream }));
			}
		}
	}
	
	return null;
}
//*********************************************************************************
context("Certificate Transparency Log V1", () =>
{
	//region Initial variables
	const log = new LogV1({
		url: "ct.googleapis.com/rocketeer/",
		key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIFsYyDzBi7MxCAC/oJBXK7dHjG+1aLCOkHjpoHPqTyghLpzA9BYbqvnV16mAw04vUjyYASVGJCUoI3ctBcJAeg==",
		fetch,
		encode
	});
	//endregion
	
	it("Monitor/Auditor client", async () =>
	{
		//region Get and verify Signed Tree Head
		const sth = await log.get_sth();
		const sthVerificationResult = await sth.verify(log.key);
		assert.deepStrictEqual(sthVerificationResult, true, "Incorrect signature for current Signed Tree Head");
		//endregion
		
		//region Get set of entries
		const entries = await log.get_entries(sth.treeSize - 100, sth.treeSize - 1);
		assert.notDeepStrictEqual(entries.length, 0, "Can not get entries from the log");
		//endregion
		
		//region Calculate previous root hash using inclusion proof array (emulated Certificate Transparency Monitor functionality)
		const singleEntry = await log.get_entries(sth.treeSize - 60, sth.treeSize - 60);
		
		const singleEntryProof = await log.get_proof_by_hash(singleEntry[0].leaf, sth.treeSize - 50);
		const previousRootHash = await utils.calculateRootHashByProof(singleEntry[0].leaf, singleEntryProof.leaf_index, sth.treeSize - 50, singleEntryProof.audit_path);
		
		const consistency = await log.get_sth_consistency(sth.treeSize - 50, sth.treeSize);
		const verifyConsistencyResult = await utils.verifyConsistency(sth.treeSize - 50, previousRootHash.r, sth.treeSize, sth.rootHash, consistency);
		
		assert.deepStrictEqual(verifyConsistencyResult, true, "Consistency was not verified against calculated previous Tree Head hash");
		//endregion
		
		//region Perform checking for signatures for each entry (performing signature verification in order to prevent from MITM attack)
		for(const entry of entries)
		{
			//region Initial variables
			let sct;
			let data;
			//endregion

			//region Check proof of inclusion first
			const proof = await log.get_proof_by_hash(entry.leaf, sth.treeSize);
			const inclusionProofVerification = await utils.verifyInclusionProof(entry.leaf, proof.leaf_index, sth.treeSize, sth.rootHash, proof.audit_path);
			
			assert.deepStrictEqual(inclusionProofVerification, true, "Inclusion proof was not verified");
			//endregion
			
			//region Prepare verification data for entry type = x509_entry
			if(entry.leaf.entry.entryType === LogEntryType.constants("x509_entry"))
			{
				sct = await log.add_chain([
					entry.leaf.entry.signedEntry,
					...entry.extra_data
				]);
				
				//region Find and verify SCT Extension data from certificate
				const sctForVerification = sctFromCertificate(entry.leaf.entry.signedEntry, sct.logID);
				if(sctForVerification !== null)
				{
					const issuer = await findIssuer(entry.leaf.entry.signedEntry, entry.extra_data);

					const preCertificate = await PreCert.fromCertificateAndIssuer({
						certificate: entry.leaf.entry.signedEntry,
						issuer: issuer
					});
					
					const sctVerificationResult = await sctForVerification.verify(preCertificate.buffer, log.key, LogEntryType.constants("precert_entry"));
					
					assert.deepStrictEqual(sctVerificationResult, true, "Incorrectly encoded SCT in one of the certificate");
				}
				//endregion

				data = entry.leaf.entry.signedEntry.toSchema().toBER(false);
			}
			//endregion
			//region Prepare verification data for entry type = precert_entry
			else // precert_entry
			{
				sct = await log.add_pre_chain([
					entry.extra_data.pre_certificate,
					...entry.extra_data.precertificate_chain
				]);
				
				const issuer = await findIssuer(entry.extra_data.pre_certificate, entry.extra_data.precertificate_chain);
				assert.notDeepStrictEqual(issuer, null, "Can not find issuer for one of the pre-certificate");
				
				const preCert = await PreCert.fromCertificateAndIssuer({
					certificate: entry.extra_data.pre_certificate,
					issuer
				});
				
				data = preCert.buffer;
			}
			//endregion
			
			//region Perform signed certificate timestamp verification
			const sctVerificationResult = await sct.verify(
				data,
				log.key,
				entry.leaf.entry.entryType
			);
			assert.deepStrictEqual(sctVerificationResult, true, "Can not validate signature for one of entries");
			//endregion
		}
		//endregion
	});
});
//*********************************************************************************
