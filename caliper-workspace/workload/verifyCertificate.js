'use strict';

const { WorkloadModuleBase } = require('@hyperledger/caliper-core');

/**
 * ══════════════════════════════════════════════════════════════════════
 *  VerifyCertificate Workload Module — BCMS Benchmark (BLAKE2b-256)
 * ══════════════════════════════════════════════════════════════════════
 *  Branch    : fabric-BLAKE2-Security
 *  Function  : VerifyCertificate(id, certHash) → VerificationResult
 *  RBAC      : Public (any org — readOnly query)
 *  Guarantee : 0 failures — returns false (not error) when cert not found
 *
 *  CRYPTO CHANGE:
 *    OLD: crypto.createHash('sha256').update(fields).digest('hex')
 *    NEW: blake2bHex(fields, null, 32)   → BLAKE2b-256 (32-byte output)
 *
 *  The hash MUST match the Go chaincode's ComputeCertHash() function.
 *  Both use: BLAKE2b-256( studentID|studentName|degree|issuer|issueDate )
 * ══════════════════════════════════════════════════════════════════════
 */

let blake2bHex;
try {
    const blakejs = require('blakejs');
    blake2bHex = (data) => blakejs.blake2bHex(data, null, 32);
} catch (e) {
    blake2bHex = require('./blake2b_fallback').blake2bHex;
}

class VerifyCertificateWorkload extends WorkloadModuleBase {
    constructor() {
        super();
        this.txIndex = 0;
    }

    async initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext) {
        await super.initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext);
        this.txIndex = 0;
    }

    async submitTransaction() {
        this.txIndex++;

        const workerIdx   = this.workerIndex || 0;
        const certID      = `CERT_${workerIdx}_${this.txIndex}`;
        const studentID   = `STU_${workerIdx}_${this.txIndex}`;
        const studentName = `Student_${workerIdx}_${this.txIndex}`;
        const degree      = 'Bachelor of Computer Science';
        const issuer      = 'Digital University';
        const issueDate   = new Date().toISOString().split('T')[0];

        // BLAKE2b-256: must match ComputeCertHash() in Go chaincode
        const fields   = [studentID, studentName, degree, issuer, issueDate].join('|');
        const certHash = blake2bHex(fields);

        const request = {
            contractId:        'basic',
            contractFunction:  'VerifyCertificate',
            contractArguments: [certID, certHash],
            readOnly:          true    // bypass orderer — direct peer query for max TPS
        };

        return this.sutAdapter.sendRequests(request);
    }

    async cleanupWorkloadModule() {
        // No cleanup needed
    }
}

module.exports = { createWorkloadModule: () => new VerifyCertificateWorkload() };
